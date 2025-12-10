#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import zipfile
from base64 import urlsafe_b64decode
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urlerror
from urllib import request

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - verification will gracefully degrade
    Ed25519PublicKey = None  # type: ignore[assignment]

from agent.config import AgentConfig, load_config as load_agent_config
from agent.sender import run_sender_loop
from agent.receiver import run_receiver_loop


# ---------------------------
# Helpers: hashing + JSON
# ---------------------------

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

def _compute_merkle_root_from_manifest_files(files: List[Dict[str, Any]]) -> str:
    """
    Compute Merkle root CID from manifest-style file entries:

      { "path": "files/...", "sha256": "<64-hex>", "size_bytes": int }

    using the same rules as oc/api/app/crypto/merkle.py.
    """
    entries: List[tuple[str, bytes]] = []

    for fe in files:
        if not isinstance(fe, dict):
            raise ValueError("files entries must be objects")
        path = fe.get("path")
        h = fe.get("sha256")
        if not isinstance(path, str) or not isinstance(h, str):
            raise ValueError("files entries must provide 'path' and 'sha256' strings")
        if not path.startswith("files/"):
            raise ValueError("manifest file path must start with 'files/'")
        if ".." in path or "\\" in path:
            raise ValueError("manifest file path must not contain '..' or backslashes")
        if len(h) != 64:
            raise ValueError("sha256 must be 64 hex characters")
        try:
            digest = bytes.fromhex(h)
        except ValueError:
            raise ValueError("sha256 must be valid hex")
        entries.append((path, digest))

    if not entries:
        raise ValueError("cannot compute Merkle root for empty file list")

    entries.sort(key=lambda item: item[0])

    level: List[bytes] = []
    for _, digest in entries:
        level.append(hashlib.sha256(b"leaf:" + digest).digest())

    while len(level) > 1:
        next_level: List[bytes] = []
        i = 0
        n = len(level)
        while i < n:
            left = level[i]
            if i + 1 < n:
                right = level[i + 1]
                i += 2
                node = hashlib.sha256(b"node:" + left + right).digest()
            else:
                i += 1
                node = left
            next_level.append(node)
        level = next_level

    root_hex = level[0].hex()
    return "cid:sha256:" + root_hex

def _manifest_unsigned_bytes(manifest: Dict[str, Any]) -> bytes:
    """
    Compute canonical bytes for the *unsigned* manifest view.

    This strips the signature field (if present) and then applies the same
    deterministic JSON encoding rules we use elsewhere. This is the payload
    that Core will eventually sign with Ed25519.
    """
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    return _canonical_json_bytes(unsigned)


def _collect_files_for_manifest(input_dir: Path) -> List[Dict[str, Any]]:
    """
    Walk input_dir recursively and return file entries for the manifest:
      - path: "files/<relative-posix-path>"
      - sha256: hex digest
      - size_bytes: file size in bytes
    """
    input_dir = input_dir.resolve()
    entries: List[Dict[str, Any]] = []
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(input_dir)
        internal = Path("files") / rel
        data = p.read_bytes()
        entries.append(
            {
                "path": internal.as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
        )
    return entries


def _compute_bundle_id(entries: List[Tuple[str, bytes]]) -> str:
    """
    Stable bundle id over arcname + sha256(content).
    """
    h = hashlib.sha256()
    for name, data in sorted(entries, key=lambda x: x[0]):
        h.update(name.encode("utf-8"))
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()[:16]


# ---------------------------
# Core HTTP client (seal + JWKS + TL entry)
# ---------------------------

def _http_json(
    url: str,
    method: str = "GET",
    body: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None,
    timeout_s: float = 10.0,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    data_bytes: Optional[bytes]
    if body is None:
        data_bytes = None
    else:
        data_bytes = json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    req = request.Request(url, data=data_bytes, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError(f"{url} did not return a JSON object")
    return obj


def _seal_via_core(
    base_url: str,
    api_key: Optional[str],
    org_id: str,
    batch_id: str,
    files: List[Dict[str, Any]],
    tl_mode: str,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Call Core /v1/seal with file metadata and return (manifest, tl_proof | None).
    """
    url = base_url.rstrip("/") + "/v1/seal"
    body = {
        "org_id": org_id,
        "batch_id": batch_id,
        "hash_alg": "sha256",
        "files": files,
        "tl_mode": tl_mode,
    }
    obj = _http_json(url, method="POST", body=body, api_key=api_key)
    manifest = obj.get("manifest")
    if not isinstance(manifest, dict):
        raise RuntimeError("/v1/seal: missing or invalid 'manifest' in response")
    tl_obj = obj.get("tl") or {}
    tl_proof = tl_obj.get("proof")
    if isinstance(tl_proof, dict):
        return manifest, tl_proof
    return manifest, None


def _fetch_jwks_snapshot(base_url: str, api_key: Optional[str]) -> Dict[str, Any]:
    """
    Fetch current JWKS from Core /v1/jwks.
    """
    url = base_url.rstrip("/") + "/v1/jwks"
    obj = _http_json(url, method="GET", body=None, api_key=api_key)
    keys = obj.get("keys")
    if not isinstance(keys, list) or not keys:
        raise RuntimeError("JWKS from Core must contain at least one key")
    return obj


def _fetch_tl_entry(
    base_url: str,
    seq: int,
    timeout_s: float = 5.0,
) -> Dict[str, Any]:
    """
    Optional online TL check: GET /v1/tl/entries/{seq}
    """
    url = base_url.rstrip("/") + f"/v1/tl/entries/{seq}"
    headers: Dict[str, str] = {"Accept": "application/json"}
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError("TL entry response must be a JSON object")
    return obj


# ---------------------------
# Bundle creation (oord seal)
# ---------------------------

def _build_bundle(
    manifest: Dict[str, Any],
    tl_proof: Optional[Dict[str, Any]],
    jwks: Dict[str, Any],
    input_dir: Path,
    out_dir: Path,
) -> Path:
    """
    Build an Oord bundle ZIP (deterministic):
      - manifest.json
      - tl_proof.json (if present)
      - jwks_snapshot.json
      - files/... (payload files as per manifest.files[].path)
    """
    files_to_write: List[Tuple[str, bytes]] = []

    # Bundle layout: manifest.json stores the *signed* manifest as canonical JSON.
    mbytes = _canonical_json_bytes(manifest)
    files_to_write.append(("manifest.json", mbytes))

    if tl_proof is not None:
        tl_bytes = _canonical_json_bytes(tl_proof)
        files_to_write.append(("tl_proof.json", tl_bytes))

    jwks_bytes = _canonical_json_bytes(jwks)
    files_to_write.append(("jwks_snapshot.json", jwks_bytes))

    # Payload files as defined in manifest.files
    for fe in manifest.get("files", []):
        if not isinstance(fe, dict):
            continue
        path = fe.get("path")
        if not isinstance(path, str):
            continue
        internal = path
        # Manifest paths are "files/<relative-posix-path>"
        rel_part = path
        if internal.startswith("files/"):
            rel_part = internal[len("files/") :]
        disk_path = input_dir / Path(rel_part)
        if not disk_path.is_file():
            raise RuntimeError(f"manifest refers to missing file on disk: {internal}")
        data = disk_path.read_bytes()
        files_to_write.append((internal, data))

    # Deterministic ordering of all entries by archive name
    files_to_write_sorted = sorted(files_to_write, key=lambda x: x[0])

    # Bundle id is derived from the sorted entries
    bundle_id = _compute_bundle_id(files_to_write_sorted)
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / f"oord_bundle_{bundle_id}.zip"
    tmp_path = bundle_path.with_suffix(".zip.tmp")

    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in files_to_write_sorted:
            info = zipfile.ZipInfo(filename=name)
            # Fixed timestamp for deterministic zips
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)

    tmp_path.replace(bundle_path)
    return bundle_path


def _cmd_seal(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir).expanduser().resolve()
    if not input_dir.is_dir():
        print(f"❌ input_dir is not a directory: {input_dir}", file=sys.stderr)
        return 2

    out_dir = Path(args.out or ".").expanduser().resolve()
    core_url = (
        args.core_url
        or os.environ.get("OORD_CORE_URL")
        or "http://127.0.0.1:8000"
    )
    api_key = args.api_key or os.environ.get("OORD_CORE_API_KEY")

    tl_mode = args.tl_mode
    if tl_mode not in ("required", "best_effort", "none"):
        print(
            f"❌ invalid tl_mode={tl_mode!r} (expected required|best_effort|none)",
            file=sys.stderr,
        )
        return 2

    files = _collect_files_for_manifest(input_dir)
    if not files:
        print("❌ no files found under input_dir", file=sys.stderr)
        return 2

    org_id = args.org_id or "ORG-LOCAL"
    batch_id = args.batch_id or input_dir.name

    try:
        manifest, tl_proof = _seal_via_core(
            core_url,
            api_key,
            org_id,
            batch_id,
            files,
            tl_mode=tl_mode,
        )
        jwks = _fetch_jwks_snapshot(core_url, api_key)
        bundle_path = _build_bundle(manifest, tl_proof, jwks, input_dir, out_dir)
    except (urlerror.URLError, TimeoutError) as e:
        print(f"❌ Core unreachable: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"❌ seal failed: {e}", file=sys.stderr)
        return 2

    print(str(bundle_path))
    return 0


# ---------------------------
# Verification (oord verify)
# ---------------------------

def _load_manifest(z: zipfile.ZipFile) -> Dict[str, Any]:
    try:
        raw = z.read("manifest.json").decode("utf-8")
    except KeyError:
        raise RuntimeError("manifest.json missing from bundle")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"manifest.json is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise RuntimeError("manifest.json must be a JSON object")
    return obj


def _check_hashes_from_manifest(
    z: zipfile.ZipFile,
    manifest: Dict[str, Any],
) -> Tuple[bool, List[Dict[str, str]]]:
    mismatches: List[Dict[str, str]] = []
    files = manifest.get("files") or []
    if not isinstance(files, list):
        mismatches.append({"file": "<manifest>", "reason": "files_not_array"})
        return False, mismatches

    expected_paths: List[str] = []
    for fe in files:
        if not isinstance(fe, dict):
            mismatches.append({"file": "<?>", "reason": "invalid_manifest_entry"})
            continue
        path = fe.get("path")
        sha_expected = fe.get("sha256")
        size_expected = fe.get("size_bytes")
        if not isinstance(path, str) or not isinstance(sha_expected, str) or not isinstance(
            size_expected, int
        ):
            mismatches.append(
                {"file": str(path), "reason": "invalid_manifest_entry"}
            )
            continue
        expected_paths.append(path)
        try:
            data = z.read(path)
        except KeyError:
            mismatches.append(
                {
                    "file": path,
                    "reason": "missing_from_zip",
                    "expected": sha_expected,
                }
            )
            continue
        sha_actual = _sha256_bytes(data)
        if sha_actual != sha_expected:
            mismatches.append(
                {
                    "file": path,
                    "reason": "hash_mismatch",
                    "actual": sha_actual,
                    "expected": sha_expected,
                }
            )
        if len(data) != size_expected:
            mismatches.append(
                {
                    "file": path,
                    "reason": "size_mismatch",
                    "actual": str(len(data)),
                    "expected": str(size_expected),
                }
            )

    # Extra files under files/ not referenced in manifest
    names = set(z.namelist())
    for name in sorted(n for n in names if n.startswith("files/")):
        if name not in expected_paths:
            data = z.read(name)
            mismatches.append(
                {
                    "file": name,
                    "reason": "missing_from_manifest",
                    "actual": _sha256_bytes(data),
                }
            )

    return len(mismatches) == 0, mismatches


def _load_tl_proof(z: zipfile.ZipFile) -> Dict[str, Any]:
    try:
        raw = z.read("tl_proof.json").decode("utf-8")
    except KeyError:
        raise RuntimeError("tl_proof.json missing from bundle")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"tl_proof.json is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise RuntimeError("tl_proof.json must be a JSON object")
    return obj


def _normalize_tl_fields(
    tl_obj: Dict[str, Any]
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Extract (merkle_root, seq, sth_sig, signer_kid) from various TL proof shapes.
    Supports both nested (entry/sth) and flat forms.
    """
    entry = tl_obj.get("entry") or {}
    sth = tl_obj.get("sth") or {}

    merkle_root = entry.get("merkle_root")
    seq = entry.get("seq")
    sth_sig = sth.get("sth_sig")
    signer_kid = entry.get("signer_key_id") or entry.get("signer_kid")

    if merkle_root is None:
        merkle_root = tl_obj.get("merkle_root")
    if seq is None:
        seq = tl_obj.get("tl_seq") or tl_obj.get("seq")
    if sth_sig is None:
        sth_sig = tl_obj.get("sth_sig")
    if signer_kid is None:
        signer_kid = tl_obj.get("signer_key_id") or tl_obj.get("signer_kid")

    if isinstance(seq, str) and seq.isdigit():
        seq_int: Optional[int] = int(seq)
    elif isinstance(seq, (int, float)):
        seq_int = int(seq)
    else:
        seq_int = None

    return merkle_root, seq_int, sth_sig, signer_kid


def _load_jwks(z: zipfile.ZipFile) -> Dict[str, Any]:
    try:
        raw = z.read("jwks_snapshot.json").decode("utf-8")
    except KeyError:
        raise RuntimeError("jwks_snapshot.json missing from bundle")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"jwks_snapshot.json is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise RuntimeError("jwks_snapshot.json must be a JSON object")
    return obj


def _jwks_fingerprint(jwks: Dict[str, Any]) -> str:
    raw = json.dumps(jwks, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _verify_tl_signature(
    merkle_root: Optional[str],
    seq: Optional[int],
    sth_sig: Optional[str],
    jwks: Dict[str, Any],
    signer_kid: Optional[str],
) -> Tuple[Optional[bool], Optional[str]]:
    """
    Verify the TL STH signature using JWKS.

    Returns:
      (True, None)   -> signature verified OK
      (False, err)   -> verification attempted and failed
      (None, None)   -> verification not attempted (stub-kid or missing fields)
    """
    if (
        merkle_root is None
        or seq is None
        or not sth_sig
        or not signer_kid
        or Ed25519PublicKey is None
    ):
        return None, None

    if signer_kid == "stub-kid":
        return None, None

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == signer_kid), None)
    if not key:
        return False, f"signer_kid {signer_kid!r} not found in JWKS"
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False, "JWKS key is not an Ed25519 OKP key"

    x_b64 = key.get("x")
    if not x_b64:
        return False, "JWKS key missing 'x' field"

    try:
        pub_bytes = urlsafe_b64decode(x_b64 + "===")
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid JWKS x encoding: {e!s}"

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid Ed25519 public key bytes: {e!s}"

    msg = f"seq={seq}|merkle_root={merkle_root}".encode("utf-8")
    try:
        sig_bytes = urlsafe_b64decode(sth_sig + "===")
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid sth_sig encoding: {e!s}"

    try:
        pub.verify(sig_bytes, msg)
    except Exception:
        return False, "TL signature verification failed"

    return True, None

def _verify_manifest_signature(
    manifest: Dict[str, Any],
    jwks: Dict[str, Any],
) -> Tuple[Optional[bool], Optional[str]]:
    """
    Verify SealManifest.signature using JWKS.

    Returns:
      (True, None)   -> signature verified OK
      (False, err)   -> verification attempted and failed
      (None, None)   -> verification not attempted (stub-kid, missing crypto, etc.)
    """
    if Ed25519PublicKey is None:
        return None, None

    key_id = manifest.get("key_id")
    sig = manifest.get("signature")
    if not isinstance(key_id, str) or not isinstance(sig, str):
        return False, "manifest missing 'key_id' or 'signature'"

    # Stub mode: Core used stub-kid + non-Ed25519 signature. We rely on hash checks only.
    if key_id == "stub-kid":
        return None, None

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == key_id), None)
    if not key:
        return False, f"manifest key_id {key_id!r} not found in JWKS"
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False, "JWKS key for manifest is not an Ed25519 OKP key"

    x_b64 = key.get("x")
    if not x_b64:
        return False, "JWKS key for manifest missing 'x' field"

    try:
        pub_bytes = urlsafe_b64decode(x_b64 + "===")
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid JWKS x encoding for manifest key: {e!s}"

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid Ed25519 public key bytes for manifest key: {e!s}"

    unsigned = _manifest_unsigned_bytes(manifest)
    try:
        sig_bytes = urlsafe_b64decode(sig + "===")
    except Exception as e:  # pragma: no cover - defensive
        return False, f"invalid manifest signature encoding: {e!s}"

    try:
        pub.verify(sig_bytes, unsigned)
    except Exception:
        return False, "manifest signature verification failed"

    return True, None


def _online_tl_check(
    tl_url_base: str,
    seq: int,
    merkle_root: str,
    sth_sig: Optional[str],
) -> Tuple[bool, Optional[str]]:
    """
    Online TL consistency check against Core /v1/tl/entries/{seq}.

    We reuse _normalize_tl_fields so this tolerates both the current flat TL
    entry shape and any nested entry/sth variants without hard-coding field
    names here.
    """
    base = tl_url_base.rstrip("/")
    url = f"{base}/v1/tl/entries/{seq}"
    try:
        obj = _http_json(url, method="GET", body=None, api_key=None, timeout_s=5.0)
    except (
        urlerror.URLError,
        TimeoutError,
        RuntimeError,
        json.JSONDecodeError,
        ValueError,
    ) as e:
        return False, f"TL online lookup failed: {e}"

    # Allow either { entry: { ... } } or a flat entry object.
    entry = obj.get("entry") or obj
    live_root, live_seq, live_sth, _ = _normalize_tl_fields(entry)

    if live_seq is None or live_root is None:
        return False, "TL entry missing seq/merkle_root"

    if live_seq != seq or live_root != merkle_root:
        return False, f"TL mismatch (live seq={live_seq}, root={live_root})"

    if sth_sig and live_sth and live_sth != sth_sig:
        return False, "TL STH signature mismatch"

    return True, None


def verify_bundle(path: Path, tl_url: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
    summary: Dict[str, Any] = {
        "bundle_path": str(path),
        "error": None,
        "error_kind": None,  # "env" for usage/env errors
        "hashes_ok": False,
        "hash_mismatches": [],
        "tl": {
            "present": False,
            "ok": False,
            "seq": None,
            "merkle_root": None,
            "sth_sig": None,
            "signer_kid": None,
            "sig_verified": None,
            "error": None,
        },
        "jwks": {
            "present": False,
            "ok": False,
            "kids": [],
            "fingerprint": None,
            "error": None,
        },
        "manifest_sig": {
            "ok": None,
            "key_id": None,
            "sig_verified": None,
            "error": None,
        },
        "tl_online": {
            "enabled": bool(tl_url),
            "ok": None,
            "error": None,
        },
    }


    if not path.is_file():
        summary["error"] = "bundle path does not exist or is not a file"
        summary["error_kind"] = "env"
        return False, summary

    try:
        with zipfile.ZipFile(path, "r") as z:
            manifest = _load_manifest(z)
            hashes_ok, mismatches = _check_hashes_from_manifest(z, manifest)
            summary["hashes_ok"] = hashes_ok
            summary["hash_mismatches"] = mismatches
            if not hashes_ok:
                return False, summary

            # TL proof (optional for now)
            tl_obj: Optional[Dict[str, Any]] = None
            try:
                tl_obj = _load_tl_proof(z)
            except RuntimeError as e:
                msg = str(e)
                # If tl_proof.json is simply missing, treat TL as "not present" but
                # do not fail verification. This covers tl_mode=none bundles.
                if "tl_proof.json missing from bundle" in msg:
                    summary["tl"]["present"] = False
                    summary["tl"]["ok"] = None
                    summary["tl"]["error"] = msg
                    tl_obj = None
                else:
                    # Any other TL error (bad JSON, wrong shape, etc.) is a hard failure.
                    summary["tl"]["present"] = False
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = msg
                    if not summary.get("error"):
                        summary["error"] = msg
                    return False, summary

            merkle_root: Optional[str] = None
            seq: Optional[int] = None
            sth_sig: Optional[str] = None
            signer_kid: Optional[str] = None

            if tl_obj is not None:
                merkle_root, seq, sth_sig, signer_kid = _normalize_tl_fields(tl_obj)
                if merkle_root is None or seq is None:
                    summary["tl"]["present"] = True
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = "tl_proof.json missing merkle_root or seq"
                    return False, summary

                summary["tl"].update(
                    {
                        "present": True,
                        "ok": True,
                        "seq": seq,
                        "merkle_root": merkle_root,
                        "sth_sig": sth_sig,
                        "signer_kid": signer_kid,
                        "sig_verified": None,
                        "error": None,
                    }
                )

            # JWKS snapshot (always required for signature verification)
            try:
                jwks = _load_jwks(z)
            except RuntimeError as e:
                summary["jwks"]["present"] = False
                summary["jwks"]["ok"] = False
                summary["jwks"]["error"] = str(e)
                if not summary.get("error"):
                    summary["error"] = str(e)
                return False, summary

            kids: List[str] = []
            for k in jwks.get("keys", []):
                kid = k.get("kid")
                if kid:
                    kids.append(kid)

            summary["jwks"].update(
                {
                    "present": True,
                    "ok": True,
                    "kids": kids,
                    "fingerprint": _jwks_fingerprint(jwks),
                    "error": None,
                }
            )

            # Manifest signature verification (Ed25519 in live mode, stub ignored)
            summary["manifest_sig"]["key_id"] = manifest.get("key_id")
            ok_manifest_sig, ms_err = _verify_manifest_signature(manifest, jwks)
            summary["manifest_sig"]["sig_verified"] = ok_manifest_sig
            summary["manifest_sig"]["error"] = ms_err

            if ok_manifest_sig is False:
                summary["manifest_sig"]["ok"] = False
                if not summary.get("error"):
                    summary["error"] = ms_err or "manifest signature verification failed"
                return False, summary
            else:
                summary["manifest_sig"]["ok"] = ok_manifest_sig

            # TL signature verification (only if TL proof present)
            if tl_obj is not None and merkle_root is not None and seq is not None:
                ok_sig, sig_err = _verify_tl_signature(
                    merkle_root=merkle_root,
                    seq=int(seq),
                    sth_sig=sth_sig,
                    jwks=jwks,
                    signer_kid=signer_kid,
                )
                summary["tl"]["sig_verified"] = ok_sig
                if ok_sig is False:
                    summary["tl"]["ok"] = False
                    summary["tl"]["error"] = sig_err or "TL signature verification failed"
                    if not summary.get("error"):
                        summary["error"] = summary["tl"]["error"]
                    return False, summary

            # Optional online TL check (only makes sense if TL proof exists)
            if tl_url and tl_obj is not None and seq is not None and merkle_root is not None:
                ok_online, err = _online_tl_check(tl_url, int(seq), merkle_root, sth_sig)
                summary["tl_online"]["enabled"] = True
                summary["tl_online"]["ok"] = ok_online
                summary["tl_online"]["error"] = err
                if not ok_online:
                    is_unreachable = bool(err and err.startswith("TL online lookup failed:"))
                    if not is_unreachable:
                        if not summary.get("error"):
                            summary["error"] = err or "online TL mismatch"
                        return False, summary
            else:
                summary["tl_online"]["enabled"] = bool(tl_url)
                summary["tl_online"]["ok"] = None
                summary["tl_online"]["error"] = None

    except zipfile.BadZipFile as e:
        summary["error"] = f"bad zip file: {e}"
        summary["error_kind"] = "env"
        return False, summary
    except RuntimeError as e:
        summary["error"] = str(e)
        return False, summary

    return True, summary


def _print_human(summary: Dict[str, Any], ok: bool) -> None:
    print(f"Bundle: {summary['bundle_path']}")

    print(f"Hashes: {'OK' if summary['hashes_ok'] else 'FAIL'}")
    if not summary["hashes_ok"]:
        for m in summary.get("hash_mismatches", []):
            reason = m.get("reason", "mismatch")
            print(f"  - {reason}: {m}")

    tl = summary.get("tl", {})
    if tl.get("present"):
        print(
            f"TL: {'OK' if tl.get('ok') else 'FAIL'} "
            f"(seq={tl.get('seq')}, root={tl.get('merkle_root')}, "
            f"kid={tl.get('signer_kid') or '-'}, "
            f"sth_sig={tl.get('sth_sig') or '-'}, "
            f"sig_verified={tl.get('sig_verified')})"
        )
        if not tl.get("ok") and tl.get("error"):
            print(f"  TL error: {tl['error']}")
    else:
        print("TL: MISSING")

    jwks = summary.get("jwks", {})
    if jwks.get("present"):
        print(
            f"JWKS: {'OK' if jwks.get('ok') else 'FAIL'} "
            f"(kids={','.join(jwks.get('kids') or []) or '-'}, "
            f"fp={jwks.get('fingerprint') or '-'})"
        )
        if not jwks.get("ok") and jwks.get("error"):
            print(f"  JWKS error: {jwks['error']}")
    else:
        print("JWKS: MISSING")

    tl_online = summary.get("tl_online", {})
    if tl_online.get("enabled"):
        print(f"TL (online): {'OK' if tl_online.get('ok') else 'FAIL'}")
        if tl_online.get("error"):
            print(f"  TL online error: {tl_online['error']}")
    else:
        print("TL (online): SKIPPED")

    print("OK" if ok else "FAIL")


def _cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.bundle).expanduser().resolve()
    ok, summary = verify_bundle(path, tl_url=args.tl_url)

    # strict TL unreachable handling
    if (
        args.strict
        and summary.get("tl_online", {}).get("enabled")
        and summary.get("tl_online", {}).get("ok") is False
    ):
        err = summary.get("tl_online", {}).get("error") or ""
        if err.startswith("TL online lookup failed:"):
            summary["error_kind"] = "env"
            if not summary.get("error"):
                summary["error"] = err
            ok = False

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        _print_human(summary, ok)

    if ok:
        return 0
    return 2 if summary.get("error_kind") == "env" else 1


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(prog="oord", description="Oord CLI (seal / verify)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # oord seal
    p_seal = subparsers.add_parser("seal", help="Seal a folder into an Oord bundle")
    p_seal.add_argument("--input-dir", required=True, help="Folder of files to seal")
    p_seal.add_argument(
        "--out",
        help="Output directory for bundle (default: current directory)",
    )
    p_seal.add_argument(
        "--core-url",
        help="Core base URL (default: $OORD_CORE_URL or http://127.0.0.1:8000)",
    )
    p_seal.add_argument(
        "--api-key",
        help="Core API key for Authorization: Bearer <key> (default: $OORD_CORE_API_KEY)",
    )
    p_seal.add_argument(
        "--org-id",
        help="Org id to embed in manifest (default: ORG-LOCAL)",
    )
    p_seal.add_argument(
        "--batch-id",
        help="Batch id to embed in manifest (default: input-dir name)",
    )
    p_seal.add_argument(
        "--tl-mode",
        default="required",
        help="TL mode for /v1/seal (required|best_effort|none, default: required)",
    )
    p_seal.set_defaults(func=_cmd_seal)

    # oord verify
    p_verify = subparsers.add_parser("verify", help="Verify an Oord bundle")
    p_verify.add_argument("bundle", help="Path to oord_bundle_*.zip")
    p_verify.add_argument(
        "--tl-url",
        help="Optional Core base URL for online TL verification (e.g. http://127.0.0.1:8000)",
    )
    p_verify.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable text",
    )
    p_verify.add_argument(
        "--strict",
        action="store_true",
        help="Treat TL unreachable as an error (exit code 2) instead of a soft warning",
    )
    p_verify.set_defaults(func=_cmd_verify)

        # oord agent
    p_agent = subparsers.add_parser(
        "agent",
        help="Run the Oord agent (sender or receiver) from a config file",
    )
    p_agent.add_argument(
        "--config",
        default="oord-agent.toml",
        help="Path to agent config TOML (default: oord-agent.toml)",
    )
    p_agent.add_argument(
        "--once",
        action="store_true",
        help="Process ready work once and exit instead of running as a long-lived watcher",
    )


    def _cmd_agent(args: argparse.Namespace) -> int:
        cfg_path = Path(args.config).expanduser().resolve()
        cfg: AgentConfig = load_agent_config(cfg_path)
        if cfg.mode == "sender":
            run_sender_loop(cfg, once=getattr(args, "once", False))
        elif cfg.mode == "receiver":
            run_receiver_loop(cfg, once=getattr(args, "once", False))
        else:
            print(f"❌ unknown agent mode {cfg.mode!r}", file=sys.stderr)
            return 2
        return 0  # unreachable if loops are infinite, but keeps type checkers happy

    p_agent.set_defaults(func=_cmd_agent)

    args = parser.parse_args(argv)
    code = args.func(args)
    sys.exit(code)


if __name__ == "__main__":
    main()
