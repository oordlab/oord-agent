#!/usr/bin/env python3
import json
import hashlib
import zipfile
from pathlib import Path
import importlib.util
import pytest


def _load_verify_bundle() -> object:
    """
    Load utils/verify_bundle.py as a module directly from the repo,
    ignoring any third-party 'utils' packages on sys.path.
    """
    repo_root = Path(__file__).resolve().parents[2]
    vb_path = repo_root / "utils" / "verify_bundle.py"
    if not vb_path.is_file():
        raise RuntimeError(f"verify_bundle.py not found at {vb_path}")

    spec = importlib.util.spec_from_file_location("verify_bundle", vb_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError("Unable to load spec for verify_bundle.py")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[arg-type]
    return mod


verify_bundle = _load_verify_bundle()


def _make_bundle(tmp_path: Path, tamper_tl: bool) -> Path:
    """
    Build a minimal but self-consistent compliance bundle:

    - Always includes:
        * jwks_snapshot.json
        * tl_proof.json
        * compliance_manifest.txt
    - For the "good" case (tamper_tl=False):
        * tl_proof.json bytes match the hash in manifest
        * JWKS is present and valid JSON
        * verify_bundle.py should return ok=True and exit code 0
    - For the "tampered" case (tamper_tl=True):
        * tl_proof.json contents are changed
        * manifest still carries the hash of the *good* tl_proof.json
        * verify_bundle.py should detect a hash mismatch and exit code 1
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    bundle = tmp_path / "compliance_bundle_test.zip"

    # --- 1) Good TL object and canonical bytes (what manifest "expects") ---
    good_tl_obj = {
        "tl_seq": 1,
        "merkle_root": "cid:sha256:" + ("a" * 64),
        "sth_sig": "stub-sth-sig",
    }
    good_tl_bytes = json.dumps(
        good_tl_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    # --- 2) Tampered TL bytes (only used when tamper_tl=True) ---
    if tamper_tl:
        tampered_tl_obj = dict(good_tl_obj)
        tampered_tl_obj["sth_sig"] = "stub-sth-sig-tampered"
        tl_bytes_to_write = json.dumps(
            tampered_tl_obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    else:
        tl_bytes_to_write = good_tl_bytes

    # --- 3) Minimal but valid JWKS snapshot ---
    jwks_obj = {
        "keys": [
            {
                "kid": "stub-kid",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                # 32 zero bytes as base64url, just to be well-formed
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }
        ]
    }
    jwks_bytes = json.dumps(
        jwks_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    # --- 4) Manifest hashes over the *expected* bytes ---
    # Note: tl_proof.json hash always uses good_tl_bytes, even when we tamper
    jwks_hash = hashlib.sha256(jwks_bytes).hexdigest()
    tl_hash = hashlib.sha256(good_tl_bytes).hexdigest()

    manifest_lines = [
        f"{jwks_hash}  jwks_snapshot.json",
        f"{tl_hash}  tl_proof.json",
    ]
    manifest_bytes = ("\n".join(manifest_lines) + "\n").encode("utf-8")

    # --- 5) Assemble the ZIP ---
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("jwks_snapshot.json", jwks_bytes)
        z.writestr("tl_proof.json", tl_bytes_to_write)
        z.writestr("compliance_manifest.txt", manifest_bytes)

    return bundle

def test_verify_bundle_good_ok(tmp_path: Path) -> None:
    """Good bundle: hashes ok, TL/JWKS present, verify_bundle() returns ok=True."""
    bundle = _make_bundle(tmp_path, tamper_tl=False)

    ok, summary = verify_bundle.verify_bundle(bundle)

    assert ok is True
    assert summary["hashes_ok"] is True
    assert summary["hash_mismatches"] == []
    assert summary["tl"]["present"] is True
    assert summary["tl"]["ok"] is True
    assert summary["jwks"]["present"] is True
    assert summary["jwks"]["ok"] is True
    assert summary.get("error_kind") is None


def test_verify_bundle_tampered_hash_mismatch(tmp_path: Path) -> None:
    """Tampered TL proof body with unchanged manifest should fail hash check."""
    bundle = _make_bundle(tmp_path, tamper_tl=True)

    ok, summary = verify_bundle.verify_bundle(bundle)

    assert ok is False
    assert summary["hashes_ok"] is False
    assert summary["hash_mismatches"], "Expected at least one hash mismatch"
    assert summary.get("error_kind") is None


def test_cli_exit_codes_good_and_tampered(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI main() should exit 0 for good bundle and 1 for tampered bundle."""
    good_bundle = _make_bundle(tmp_path / "good", tamper_tl=False)
    bad_bundle = _make_bundle(tmp_path / "bad", tamper_tl=True)

    # Good bundle → exit 0
    with pytest.raises(SystemExit) as ei_good:
        verify_bundle.main([str(good_bundle)])
    assert ei_good.value.code == 0

    # Tampered bundle → exit 1
    with pytest.raises(SystemExit) as ei_bad:
        verify_bundle.main([str(bad_bundle)])
    assert ei_bad.value.code == 1


def test_cli_json_output_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--json should emit parseable JSON with the expected top-level keys."""
    bundle = _make_bundle(tmp_path, tamper_tl=False)

    with pytest.raises(SystemExit) as ei:
        verify_bundle.main([str(bundle), "--json"])
    assert ei.value.code == 0

    out = capsys.readouterr().out
    data = json.loads(out)

    assert data["bundle_path"].endswith(".zip")
    assert data["hashes_ok"] is True
    assert isinstance(data.get("jwks"), dict)
    assert isinstance(data.get("tl"), dict)
    assert isinstance(data.get("tl_online"), dict)


def test_cli_tl_unreachable_soft_and_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    When TL is unreachable:
      - default: TL (online) FAIL but overall exit code 0
      - --strict: exit code 2 (env/usage error)
    """
    bundle = _make_bundle(tmp_path, tamper_tl=False)

    # Force _online_tl_check to behave as "unreachable" without making real HTTP calls.
    def fake_online_check(tl_url_base: str, seq: int, merkle_root: str, sth_sig: str | None):
        return False, "TL online lookup failed: synthetic"

    monkeypatch.setattr(verify_bundle, "_online_tl_check", fake_online_check)

    # Soft mode: unreachable TL is surfaced but does not fail verification
    with pytest.raises(SystemExit) as ei_soft:
        verify_bundle.main([str(bundle), "--tl-url", "http://example.invalid"])
    assert ei_soft.value.code == 0
    out_soft = capsys.readouterr().out
    assert "TL (online): FAIL" in out_soft
    assert "TL online error:" in out_soft

    # Strict mode: unreachable TL becomes env/usage error → exit 2
    with pytest.raises(SystemExit) as ei_strict:
        verify_bundle.main(
            [str(bundle), "--tl-url", "http://example.invalid", "--strict"]
        )
    assert ei_strict.value.code == 2
    out_strict = capsys.readouterr().out
    assert "TL (online): FAIL" in out_strict
    assert "TL online error:" in out_strict
