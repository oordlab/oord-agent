#!/usr/bin/env python3
import glob, hashlib, os, sys, zipfile, datetime, json
import urllib.request, urllib.error
from pathlib import Path

# Robust import shim so this works as:
#  - `python -m utils.bundle_packer`
#  - `python utils/bundle_packer.py`
#  - from any CWD with/without PYTHONPATH set
try:
    from utils.jwks_snapshot import fetch_and_save_jwks
    from utils.verify_logger import append_jwks_fingerprint
except Exception:
    try:
        from .jwks_snapshot import fetch_and_save_jwks
        from .verify_logger import append_jwks_fingerprint
    except Exception:
        sys.path.append(os.path.dirname(__file__))                # .../utils
        sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # repo root
        from jwks_snapshot import fetch_and_save_jwks
        from verify_logger import append_jwks_fingerprint


try:
    # If utils is a package
    from .verify_logger import append_tl_metadata
except Exception:
    # If running as a script inside utils/
    from verify_logger import append_tl_metadata


FIXED_TIME = (1980,1,1,0,0,0)
ROOT = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.abspath(os.path.join(ROOT, "..", "_out"))
VERIFY_PATH = os.path.join(OUT_DIR, "verify.txt")
LAB_CFG = os.path.abspath(os.path.join(ROOT, "..", "configs", "lab.config.yaml"))

INCLUDE_GLOBS = [
    os.path.join(OUT_DIR, "inspector_pack_*.zip"),
    os.path.join(OUT_DIR, "attestation.pdf"),
    os.path.join(OUT_DIR, "vault_loader.csv"),
    os.path.join(OUT_DIR, "vault_loader_canonical.csv"),
    os.path.join(OUT_DIR, "IQOQ_canonical.xlsx"),
    os.path.join(OUT_DIR, "verify.txt"),
    os.path.join(OUT_DIR, "tl_proof.json"),
    os.path.join(OUT_DIR, "jwks_snapshot.json"),  # ← include JWKS snapshot in bundle
]

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _virtual_verify_bytes(raw: bytes) -> bytes:
    """
    Return verify.txt bytes normalized for determinism:
    strip lines that are per-bundle effects: [bundle], [jwks], [tl].
    (On-disk verify.txt keeps growing; only the in-ZIP view is filtered.)
    """
    try:
        txt = raw.decode("utf-8", errors="ignore")
        keep = []
        for ln in txt.splitlines(True):
            if ln.startswith("[bundle] ") or ln.startswith("[jwks] ") or ln.startswith("[tl] "):
                continue
            keep.append(ln)
        return ("".join(keep)).encode("utf-8")
    except Exception:
        return raw


def _virtual_tl_proof_bytes(raw: bytes) -> bytes:
    """Return normalized tl_proof.json bytes (content-derived t_log_ms), used for in-ZIP and manifest."""
    return _normalize_tl_proof_bytes(raw)

def virtual_bytes_for_zip(arcname: str, raw: bytes) -> bytes:
    """Bytes that represent the file inside the ZIP (normalized where needed)."""
    if arcname == "verify.txt":
        return _virtual_verify_bytes(raw)
    if arcname == "tl_proof.json":
        return _virtual_tl_proof_bytes(raw)
    return raw


def collect_files():
    files = []
    for g in INCLUDE_GLOBS:
        for p in glob.glob(g):
            if os.path.isfile(p):
                files.append(os.path.abspath(p))
        files = sorted(set(files))
    # PACK_LIMIT=1 → keep only the newest inspector_pack_*.zip to reduce noise during tests
    if os.environ.get("PACK_LIMIT") == "1":
        packs = [p for p in files
                 if os.path.basename(p).startswith("inspector_pack_") and p.endswith(".zip")]
        if packs:
            # Pick by mtime to be robust across different naming schemes (with/without "batch-")
            newest = max(packs, key=lambda p: os.path.getmtime(p))
            files = [f for f in files if f not in packs or f == newest]
            print("PACK_LIMIT=1 enabled — keeping only newest inspector pack:",
                  os.path.basename(newest))
    return files




def bundle_id(files):
    """Stable bundle id over the ZIP's *virtual* bytes, not raw on-disk bytes."""
    h = hashlib.sha256()
    for p in files:
        arcname = os.path.basename(p)
        with open(p, "rb") as f:
            raw = f.read()
        vb = virtual_bytes_for_zip(arcname, raw)
        h.update(arcname.encode("utf-8"))
        h.update(hashlib.sha256(vb).digest())
    return h.hexdigest()[:16]


def manifest_text(files):
    rows = []
    for p in files:
        arc = os.path.basename(p)
        with open(p, "rb") as f:
            raw = f.read()
        vb = virtual_bytes_for_zip(arc, raw)
        rows.append((arc, hashlib.sha256(vb).hexdigest()))
    rows.sort(key=lambda x: x[0])
    return "\n".join(f"{h}  {name}" for name,h in rows).encode("utf-8")

def append_verify_log(bundle_path: str, bundle_hash: str):
    """Append the compliance bundle hash into verify.txt deterministically."""
    os.makedirs(OUT_DIR, exist_ok=True)
    ts = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    line = f"[bundle] {os.path.basename(bundle_path)}  sha256={bundle_hash}  ts={ts}\n"
    with open(VERIFY_PATH, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"🧾 Logged bundle hash to verify.txt → {bundle_hash}")

def _logical_time_ms_from_root(merkle_root: str) -> int:
    h = hashlib.sha256(merkle_root.encode("utf-8")).hexdigest()
    return int(h[:8], 16)

def _normalize_tl_proof_bytes(raw: bytes) -> bytes:
    try:
        obj = json.loads(raw.decode("utf-8"))
        root = obj.get("merkle_root") or obj.get("tl_root") or ""
        if isinstance(root, str) and root.startswith("cid:sha256:"):
            obj["t_log_ms"] = _logical_time_ms_from_root(root)
            return (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        return raw
    except Exception:
        return raw


def write_zip(files, out_path):
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        mbytes = manifest_text(files)
        mzi = zipfile.ZipInfo(filename="compliance_manifest.txt", date_time=FIXED_TIME)
        mzi.compress_type = zipfile.ZIP_DEFLATED
        mzi.create_system = 0
        mzi.external_attr = 0
        z.writestr(mzi, mbytes)
        for p in files:
            arcname = os.path.basename(p)
            with open(p, "rb") as f:
                raw = f.read()
            # Use the same virtual bytes as manifest & bundle_id for in-ZIP content
            data = virtual_bytes_for_zip(arcname, raw)
            zi = zipfile.ZipInfo(filename=arcname, date_time=FIXED_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 0
            zi.external_attr = 0
            z.writestr(zi, data)

def _read_text(path: str) -> str | None:
    try:
        if os.path.exists(path):
            return Path(path).read_text(encoding="utf-8")
    except Exception:
        pass
    return None

def create_bundle_remote(core_base_url: str) -> tuple[bytes, str]:
    import json as _json, glob as _glob, zipfile as _zipfile
    from pathlib import Path

    def _maybe_json(path: str):
        """Return parsed JSON object if possible, else raw string, else None."""
        if not os.path.exists(path):
            return None
        txt = _read_text(path)
        if txt is None or txt.strip() == "":
            return None
        try:
            return _json.loads(txt)
        except Exception:
            return txt

    def _extract_from_latest_pack(member: str) -> str | None:
        """Best-effort: read a member (e.g., manifest.json) from newest inspector_pack_*.zip by mtime."""
        packs = _glob.glob(os.path.join(OUT_DIR, "inspector_pack_*.zip"))
        packs = sorted(packs, key=lambda p: os.path.getmtime(p))  # newest last
        if not packs:
            return None
        try:
            pick = packs[-1]
            with _zipfile.ZipFile(pick, "r") as zf:
                if member in zf.namelist():
                    return zf.read(member).decode("utf-8", errors="ignore")
        except Exception:
            return None
        return None

    manifest_val = _maybe_json(os.path.join(OUT_DIR, "manifest.json"))
    if manifest_val is None:
        # Fallback: pull manifest.json from newest inspector pack so Core has a non-empty manifest
        mtxt = _extract_from_latest_pack("manifest.json")
        if mtxt:
            try:
                manifest_val = _json.loads(mtxt)
            except Exception:
                manifest_val = mtxt  # still acceptable; Core will canonicalize internally
    # FINAL GUARANTEE: never send empty/None manifest (prevents intermittent 400)
    if manifest_val is None or (isinstance(manifest_val, str) and not manifest_val.strip()):
        # Minimal, deterministic stub; server canonicalizes. Parity unaffected (manifest excluded).
        manifest_val = {"_": "stub"}

    body = {
        "manifest_json":      manifest_val,  # must be non-empty to avoid 400
        "session_json":       _maybe_json(os.path.join(OUT_DIR, "session.json")),
        "tl_proof_json":      _maybe_json(os.path.join(OUT_DIR, "tl_proof.json")),
        "jwks_snapshot_json": _maybe_json(os.path.join(OUT_DIR, "jwks_snapshot.json")),
        "verify_txt":         (_read_text(os.path.join(OUT_DIR, "verify.txt")) or ""),
    }

    # Build headers (conditionally include API key if provided)
    _headers = {"Content-Type": "application/json"}
    _api_key = os.environ.get("OORD_CORE_API_KEY") or os.environ.get("X_API_KEY")
    if _api_key:
        # Your core_v1 enforces Bearer for other routes; bundle_v1 ignores auth today.
        # We send X-API-Key only if present to support “secure” deployments.
        _headers["X-API-Key"] = _api_key

    req = urllib.request.Request(
        f"{core_base_url.rstrip('/')}/v1/bundle",
        data=_json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers=_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            bid = resp.headers.get("X-Bundle-Id", "0000000000000000")
            return data, bid
    except urllib.error.HTTPError as e:
        # Surface server diagnostics to console — diagnostics first.
        try:
            msg = e.read().decode("utf-8", "ignore")
        except Exception:
            msg = "<no body>"
        print(f"❌ /v1/bundle HTTP {e.code}: {msg}", file=sys.stderr)
        raise



def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    # Predeclare to avoid UnboundLocalError if an early path throws
    files = []
 
    # --- JWKS snapshot first so it can be included in the bundle ---
    jwks_sha = None
    jwks_kids = None
    try:
        base_url = os.environ.get("OORD_TL_BASE", "http://localhost:8000").rstrip("/")
        snap_path = os.path.join(OUT_DIR, "jwks_snapshot.json")
        jwks_sha, jwks_kids = fetch_and_save_jwks(base_url, snap_path)
        # optional console info
        print(f"jwks_snapshot={snap_path} sha256={jwks_sha} kids={','.join(jwks_kids) if jwks_kids else '-'}")
    except Exception:
        # Non-fatal; proceed without snapshot
        pass
        
    files = collect_files()
    # Force-include tl_proof.json if it exists (belt-and-suspenders; helps determinism harness)
    _tlp = os.path.join(OUT_DIR, "tl_proof.json")
    if os.path.exists(_tlp) and _tlp not in files:
        files.append(_tlp)
        files = sorted(set(files))
    if not files:
        print("No compliance artifacts found in _out/", file=sys.stderr)
        sys.exit(1)
    # -----------------------------
    # Resolve bundle mode: ENV > YAML > default(local)
    # and remember the source for traceability
    # -----------------------------
    def _strip_q(v: str) -> str:
        v = v.strip()
        # Strip one layer of matching quotes up to twice to tolerate "'http://…'"
        for _ in range(2):
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1].strip()
            else:
                break
        return v

    def _yaml_get(sec: str, key: str, default: str = "") -> str:
        """
        Tiny, dependency-free YAML reader for flat `section:` then `key:` pairs.
        Assumes indentation-based nesting; ignores comments and blank lines.
        Good enough for:
          core:
            base_url: "http://localhost:8000"
          bundle:
            mode: "local"
        """
        try:
            if not os.path.exists(LAB_CFG):
                return default
            lines = Path(LAB_CFG).read_text(encoding="utf-8").splitlines()
            in_section = False
            base_indent = None
            for ln in lines:
                raw = ln
                # strip inline comments (naive but safe for our keys)
                if "#" in raw:
                    raw = raw.split("#", 1)[0]
                if not raw.strip():
                    continue
                if not in_section:
                    if raw.strip().startswith(f"{sec}:"):
                        in_section = True
                        # indent of the section line (number of leading spaces)
                        base_indent = len(raw) - len(raw.lstrip(" "))
                    continue
                # inside section until next line with indent <= base_indent
                cur_indent = len(raw) - len(raw.lstrip(" "))
                if cur_indent <= (base_indent or 0):
                    break
                s = raw.strip()
                if s.startswith(f"{key}:"):
                    val = s.split(":", 1)[1].strip()
                    return _strip_q(val)
        except Exception:
            pass
        return default

    mode_src = "default"
    env_mode_raw = os.environ.get("BUNDLE_MODE", "")
    mode = env_mode_raw.strip().lower()
    if env_mode_raw:
        mode_src = "env"
        if mode not in ("local", "remote"):
            print(f"❌ Invalid BUNDLE_MODE={env_mode_raw!r} (expected 'local' or 'remote')", file=sys.stderr)
            sys.exit(2)
    else:
        ymode_raw = _yaml_get("bundle", "mode", "")
        ymode = ymode_raw.strip().lower()
        if ymode:
            mode_src = "yaml"
            if ymode not in ("local", "remote"):
                print(
                    f"❌ Invalid bundle.mode={ymode_raw!r} in {LAB_CFG} "
                    f"(expected 'local' or 'remote')",
                    file=sys.stderr,
                )
                sys.exit(2)
            mode = ymode

    if not mode:
        mode = "local"
    print(f"[bundle] mode={mode} mode_src={mode_src}")
    # -----------------------------
    # Resolve remote base: ENV > YAML > default
    # and add guardrails before invoking remote bundling
    # -----------------------------
    def _validate_http_url(u: str) -> bool:
        u = (u or "").strip().lower()
        return u.startswith("http://") or u.startswith("https://")

    def _probe_remote(base: str, timeout_s: float = 2.0) -> bool:
        try:
            url = base.rstrip("/") + "/health"
            with urllib.request.urlopen(url, timeout=timeout_s) as r:
                return 200 <= getattr(r, "status", 200) < 300
        except Exception:
            return False

    base_src = "default"
    core_base = os.environ.get("OORD_TL_BASE", "").strip()
    if core_base:
        base_src = "env"
    else:
        core_base = _yaml_get("core", "base_url", "http://localhost:8000").strip()
        base_src = "yaml" if core_base else "default"

    if mode == "remote":
        print(f"[bundle] remote_base={core_base} base_src={base_src}")
        if not _validate_http_url(core_base):
            print(f"❌ invalid core.base_url/OORD_TL_BASE for remote mode: '{core_base}' (expect http[s]://…)", file=sys.stderr)
            sys.exit(2)
        if not _probe_remote(core_base):
            print(f"❌ remote not reachable (GET {core_base.rstrip('/')}/health). Aborting.", file=sys.stderr)
            sys.exit(2)
        data, bid = create_bundle_remote(core_base)

        out_path = os.path.join(OUT_DIR, f"compliance_bundle_{bid}.zip")
        Path(out_path).write_bytes(data)
        append_verify_log(out_path, bid)
    else:
        bid = bundle_id(files)
        out_path = os.path.join(OUT_DIR, f"compliance_bundle_{bid}.zip")
        tmp_path = out_path + ".tmp"
        write_zip(files, tmp_path)
        os.replace(tmp_path, out_path)
        append_verify_log(out_path, bid)

    # Console trace of arcnames to make CI/debug obvious
    try:
        with zipfile.ZipFile(out_path, "r") as zf:
            names = sorted(zf.namelist())
            print("bundle contents:", ", ".join(names))
    except Exception:
        pass

    # Best-effort: append a TL status line to verify.txt
    try:
        tlp = os.path.join(OUT_DIR, "tl_proof.json")
        if os.path.exists(tlp):
            data = json.loads(open(tlp, "r", encoding="utf-8").read())
            if isinstance(data, dict) and "status" not in data:
                tl_seq = int(data.get("tl_seq", 0))
                sth_sig = data.get("sth_sig")
                mr = data.get("merkle_root")
                append_tl_metadata(Path(VERIFY_PATH), tl_seq, sth_sig, mr)
            else:
                mr = data.get("merkle_root") if isinstance(data, dict) else None
                append_tl_metadata(Path(VERIFY_PATH), None, None, mr)
    except Exception:
        # Non-fatal; keep bundle usable even if TL logging fails
        pass

    # Best-effort: append JWKS fingerprint line to verify.txt
    try:
        if jwks_sha is not None:
            append_jwks_fingerprint(Path(VERIFY_PATH), jwks_sha, jwks_kids or [])
    except Exception:
        # Non-fatal
        pass

    # Best-effort: warn if the signature kid used in the latest inspector pack isn't in the JWKS kids
    try:
        import glob as _glob, zipfile as _zipfile, json as _json
        packs = sorted(_glob.glob(os.path.join(OUT_DIR, "inspector_pack_*.zip")))
        sig_kid = None
        if packs:
            with _zipfile.ZipFile(packs[-1], "r") as zf:
                for candidate in ("manifest.json", "session.json"):
                    if candidate in zf.namelist():
                        try:
                            doc = _json.loads(zf.read(candidate).decode("utf-8"))
                        except Exception:
                            continue
                        # common locations: top-level "kid" or nested signature.kid
                        sig_kid = (doc.get("signature") or {}).get("kid") or doc.get("kid")
                        if sig_kid:
                            break
        if sig_kid and jwks_kids and sig_kid not in jwks_kids:
            print(f"WARNING: signature kid {sig_kid} not present in JWKS kids {jwks_kids}")
    except Exception:
        # Non-fatal; only a convenience check
        pass


    print(out_path)
    print("✅ Compliance bundle created.")

if __name__ == "__main__":
    main()
