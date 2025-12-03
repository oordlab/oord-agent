#!/usr/bin/env python3
import argparse
import hashlib
import io
from base64 import urlsafe_b64decode
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib import request, error as urlerror
from base64 import urlsafe_b64decode

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - verification will gracefully degrade
    Ed25519PublicKey = None  # type: ignore[assignment]

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _read_first_matching(
    z: zipfile.ZipFile,
    primary: str,
    alt_suffixes: List[str],
) -> bytes:
    """
    Read a file from the zip:
      - First try an exact name match (primary).
      - Then try any entry whose name endswith() one of the alt_suffixes.
    """
    names = set(z.namelist())
    if primary in names:
        return z.read(primary)

    for suf in alt_suffixes:
        for n in names:
            if n.endswith(suf):
                return z.read(n)

    raise KeyError(primary)


def _load_compliance_manifest(z: zipfile.ZipFile) -> Dict[str, str]:
    """
    compliance_manifest.txt format (current):
      <sha256> <path>
    One per line.
    """
    try:
        raw = z.read("compliance_manifest.txt").decode("utf-8")
    except KeyError:
        raise RuntimeError("compliance_manifest.txt missing from bundle")

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    expect: Dict[str, str] = {}
    for ln in lines:
        parts = ln.split(None, 1)
        if len(parts) != 2:
            raise RuntimeError(f"invalid line in compliance_manifest.txt: {ln!r}")
        sha, path = parts[0], parts[1]
        expect[path] = sha
    return expect


def _find_inspector_pack_name(z: zipfile.ZipFile) -> str | None:
    for name in sorted(z.namelist()):
        if name.startswith("inspector_pack") and name.lower().endswith(".zip"):
            return name
    return None


def _load_session_from_inspector_pack(
    z: zipfile.ZipFile,
) -> Tuple[Dict[str, Any], Dict[str, Any]] | None:
    """
    If the compliance bundle embeds an Inspector Pack, use it to recover
    manifest/session metadata for human-readable output.
    """
    insp_name = _find_inspector_pack_name(z)
    if not insp_name:
        return None
    data = z.read(insp_name)
    with zipfile.ZipFile(io.BytesIO(data), "r") as iz:
        manifest = json.loads(iz.read("manifest.json").decode("utf-8"))
        session = json.loads(iz.read("session.json").decode("utf-8"))
    return manifest, session


def _load_tl_proof(z: zipfile.ZipFile) -> Dict[str, Any]:
    """
    Load tl_proof.json in a tolerant way.

    Supports:
      1) {"entry": {"merkle_root": "...", "seq": ...}, "sth": {"sth_sig": "..."}}
      2) {"tl_seq": ..., "merkle_root": "...", "sth_sig": "..."}
      3) {"seq": ..., "merkle_root": "...", "sth_sig": "..."}
    """
    try:
        raw = _read_first_matching(
            z,
            "tl_proof.json",
            alt_suffixes=["/tl_proof.json"],
        ).decode("utf-8")
    except KeyError:
        raise RuntimeError("tl_proof.json missing from bundle")

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"tl_proof.json is not valid JSON: {e}")

    return obj


def _normalize_tl_fields(
    tl_obj: Dict[str, Any]
) -> Tuple[str | None, int | None, str | None, str | None]:
    """
    Extract (merkle_root, seq, sth_sig, signer_kid) from various TL proof shapes.
    """
    # Case 1: transparency log style with entry/sth
    entry = tl_obj.get("entry") or {}
    sth = tl_obj.get("sth") or {}

    merkle_root = entry.get("merkle_root")
    seq = entry.get("seq")
    sth_sig = sth.get("sth_sig")
    signer_kid = entry.get("signer_key_id") or entry.get("signer_kid")

    # Case 2: flat keys (tl_seq/seq, merkle_root, sth_sig)
    if merkle_root is None:
        merkle_root = tl_obj.get("merkle_root")
    if seq is None:
        seq = tl_obj.get("tl_seq") or tl_obj.get("seq")
    if sth_sig is None:
        sth_sig = tl_obj.get("sth_sig")
    if signer_kid is None:
        signer_kid = tl_obj.get("signer_key_id") or tl_obj.get("signer_kid")


    # Ensure numeric seq if possible
    if isinstance(seq, str) and seq.isdigit():
        seq_int: int | None = int(seq)
    elif isinstance(seq, (int, float)):
        seq_int = int(seq)
    else:
        seq_int = None

    return merkle_root, seq_int, sth_sig, signer_kid

def _verify_tl_signature(
    merkle_root: str | None,
    seq: int | None,
    sth_sig: str | None,
    jwks: Dict[str, Any],
    signer_kid: str | None,
) -> Tuple[bool | None, str | None]:
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
        # Stub-mode bundles use hash-style sth_sig not backed by real Ed25519.
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



def _load_jwks(z: zipfile.ZipFile) -> Dict[str, Any]:
    """
    Load JWKS snapshot in a tolerant way.

    Supports:
      - jwks_snapshot.json
      - jwks.json
      - any entry ending with "/jwks_snapshot.json" or "/jwks.json"
    """
    try:
        raw = _read_first_matching(
            z,
            "jwks_snapshot.json",
            alt_suffixes=["/jwks_snapshot.json", "jwks.json", "/jwks.json"],
        ).decode("utf-8")
    except KeyError:
        raise RuntimeError("jwks_snapshot.json (or jwks.json) missing from bundle")

    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"jwks_snapshot.json is not valid JSON: {e}")

    return obj


def _jwks_fingerprint(jwks: Dict[str, Any]) -> str:
    raw = json.dumps(jwks, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _online_tl_check(
    tl_url_base: str,
    seq: int,
    merkle_root: str,
    sth_sig: str | None,
) -> Tuple[bool, str | None]:
    """
    Optional: compare TL entry in bundle with a live Core /v1/tl/entries/{seq}.
    """
    base = tl_url_base.rstrip("/")
    url = f"{base}/v1/tl/entries/{seq}"
    try:
        with request.urlopen(url, timeout=5) as resp:
            body = resp.read().decode("utf-8")
        obj = json.loads(body)
    except (urlerror.URLError, TimeoutError, json.JSONDecodeError, ValueError) as e:
        return False, f"TL online lookup failed: {e}"

    entry = obj.get("entry") or obj
    live_root = entry.get("merkle_root")
    live_seq = entry.get("seq")
    live_sth = entry.get("sth_sig")

    if live_seq != seq or live_root != merkle_root:
        return False, f"TL mismatch (live seq={live_seq}, root={live_root})"
    if sth_sig and live_sth and live_sth != sth_sig:
        return False, "TL STH signature mismatch"
    return True, None


def verify_bundle(path: Path, tl_url: str | None = None) -> Tuple[bool, Dict[str, Any]]:
    """
    Core verification logic. Returns (ok, summary_dict).
    """
    summary: Dict[str, Any] = {
        "bundle_path": str(path),
        "error": None,
        "error_kind": None,  # "env" for usage/env errors; None/other => verification failure
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
        "tl_online": {
            "enabled": bool(tl_url),
            "ok": None,
            "error": None,
        },
        "session": {
            "session_key": None,
            "session_id": None,
            "display_name": None,
            "company_id": None,
        },
    }

    if not path.is_file():
        summary["error"] = "bundle path does not exist or is not a file"
        summary["error_kind"] = "env"
        return False, summary

    try:
        with zipfile.ZipFile(path, "r") as z:
            # 1) Hash check via compliance_manifest.txt
            expect = _load_compliance_manifest(z)
            mismatches: List[Dict[str, str]] = []

            for name in sorted(n for n in z.namelist() if n != "compliance_manifest.txt"):
                actual = _sha256_bytes(z.read(name))
                expected = expect.get(name)
                if expected is None:
                    mismatches.append(
                        {"file": name, "reason": "missing_from_manifest", "actual": actual}
                    )
                elif expected != actual:
                    mismatches.append(
                        {
                            "file": name,
                            "reason": "hash_mismatch",
                            "actual": actual,
                            "expected": expected,
                        }
                    )

            for name in sorted(expect.keys()):
                if name not in z.namelist() and name != "compliance_manifest.txt":
                    mismatches.append(
                        {"file": name, "reason": "missing_from_zip", "expected": expect[name]}
                    )

            summary["hash_mismatches"] = mismatches
            summary["hashes_ok"] = len(mismatches) == 0
            if not summary["hashes_ok"]:
                return False, summary

            # 2) Session / company info from Inspector Pack (best-effort)
            maybe = _load_session_from_inspector_pack(z)
            if maybe is not None:
                manifest, session = maybe
                session_id = manifest.get("session_id") or session.get("study_id") or session.get("session_id")
                company_id = manifest.get("company_id") or session.get("company_id")
                session_key = manifest.get("session_key") or session.get("session_key") or session_id
                display_name = (
                    manifest.get("display_name")
                    or session.get("display_name")
                    or session.get("study_name")
                    or session.get("study_id")
                )
                summary["session"].update(
                    {
                        "session_id": session_id,
                        "session_key": session_key,
                        "display_name": display_name,
                        "company_id": company_id,
                    }
                )

            # 3) TL proof (tolerant)
            try:
                tl_obj = _load_tl_proof(z)
            except RuntimeError as e:
                summary["tl"]["present"] = False
                summary["tl"]["ok"] = False
                summary["tl"]["error"] = str(e)
                if not summary.get("error"):
                    summary["error"] = str(e)
                return False, summary

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

            # 4) JWKS snapshot (tolerant)
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

            # 5) TL signature verification (if possible)
            ok_sig, sig_err = _verify_tl_signature(
                merkle_root=merkle_root,
                seq=int(seq) if seq is not None else None,
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

            # 6) Optional online TL check
            if tl_url and seq is not None and merkle_root is not None:
                ok_online, err = _online_tl_check(tl_url, int(seq), merkle_root, sth_sig)
                summary["tl_online"]["enabled"] = True
                summary["tl_online"]["ok"] = ok_online
                summary["tl_online"]["error"] = err
                if not ok_online:
                    # Distinguish network/unreachable vs logical TL mismatch.
                    is_unreachable = bool(err and err.startswith("TL online lookup failed:"))
                    if is_unreachable:
                        # Default: soft-fail (keep overall ok) but surface in output.
                        # Strict mode will be handled by the caller via error_kind/exit code.
                        pass
                    else:
                        # TL mismatch is always a verification failure.
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
    sess = summary.get("session") or {}
    if any(sess.values()):
        print(
            f"Session: id={sess.get('session_id') or '-'} "
            f"key={sess.get('session_key') or '-'} "
            f"company={sess.get('company_id') or '-'} "
            f"name={sess.get('display_name') or '-'}"
        )

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


def main(argv: List[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Verify a compliance bundle (hashes, TL proof, JWKS)."
    )
    parser.add_argument("bundle", help="Path to compliance_bundle_*.zip")
    parser.add_argument(
        "--tl-url",
        help="Optional Core base URL for online TL verification (e.g. http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable text",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat TL unreachable as an error (exit code 2) instead of a soft warning",
    )
    args = parser.parse_args(argv)

    ok, summary = verify_bundle(Path(args.bundle), tl_url=args.tl_url)

    # If TL online check failed and strict mode is enabled, upgrade this to an env/usage error.
    if args.strict and summary.get("tl_online", {}).get("enabled") and summary.get("tl_online", {}).get("ok") is False:
        # Only treat network/unreachable as env — logical mismatches already cause ok=False above.
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
        code = 0
    else:
        # error_kind == "env" → usage/config/env error → exit 2
        # anything else (or None) → verification failure → exit 1
        code = 2 if summary.get("error_kind") == "env" else 1
    sys.exit(code)

if __name__ == "__main__":
    main()
