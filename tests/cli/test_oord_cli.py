import json
import re
import hashlib
from pathlib import Path
import zipfile

import pytest

from cli import oord_cli

def _make_files(tmp_path: Path) -> Path:
    root = tmp_path / "in"
    (root / "sub").mkdir(parents=True, exist_ok=True)
    (root / "a.txt").write_text("hello", encoding="utf-8")
    (root / "sub" / "b.txt").write_text("world", encoding="utf-8")
    return root


def test_seal_and_verify_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """
    Happy path:
      - oord seal (with Core + JWKS mocked) creates a bundle
      - oord verify passes on that bundle
    """
    input_dir = _make_files(tmp_path)
    out_dir = tmp_path / "out"

    # Fake Core /v1/seal: echo back manifest-like object, ignore TL structure details.
    def fake_seal(
        base_url: str,
        api_key: str | None,
        org_id: str,
        batch_id: str,
        files: list[dict],
        tl_mode: str,
    ):
        # Use the same Merkle computation as the real system so verify can
        # recompute and compare against manifest.merkle.root_cid.
        root_cid = oord_cli._compute_merkle_root_from_manifest_files(files)
        manifest = {
            "manifest_version": "1.0",
            "org_id": org_id,
            "batch_id": batch_id,
            "created_at_ms": 0,
            "key_id": "stub-kid",
            "hash_alg": "sha256",
            "merkle": {
                "root_cid": root_cid,
                "tree_alg": "binary_merkle_sha256",
            },
            "files": files,
            "signature": "stub-signature",
        }
        tl_proof = {
            "tl_seq": 1,
            "merkle_root": root_cid,
            "sth_sig": "stub-sth-sig",
            "signer_key_id": "stub-kid",
        }
        return manifest, tl_proof


    # Fake JWKS snapshot.
    def fake_jwks(base_url: str, api_key: str | None):
        return {
            "keys": [
                {
                    "kid": "stub-kid",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                }
            ]
        }

    monkeypatch.setattr(oord_cli, "_seal_via_core", fake_seal)
    monkeypatch.setattr(oord_cli, "_fetch_jwks_snapshot", fake_jwks)

    # Run: oord seal
    with pytest.raises(SystemExit) as ei_seal:
        oord_cli.main(
            [
                "seal",
                "--input-dir",
                str(input_dir),
                "--out",
                str(out_dir),
                "--tl-mode",
                "required",
            ]
        )
    assert ei_seal.value.code == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out, "expected bundle path printed"
    bundle_path = Path(out[-1])
    assert bundle_path.is_file()
    assert bundle_path.name.startswith("oord_bundle_")
    assert bundle_path.suffix == ".zip"

    # Layout: root files + payload layout, no legacy artifacts
    with zipfile.ZipFile(bundle_path, "r") as z:
        names = set(z.namelist())

        # Root control files
        assert "manifest.json" in names
        assert "jwks_snapshot.json" in names
        assert "tl_proof.json" in names

        # Payload layout
        assert "files/a.txt" in names
        assert "files/sub/b.txt" in names

        # No pre-pivot artifacts
        assert "receipt.txt" not in names
        assert "proof.json" not in names
        assert "inspector_pack/manifest.json" not in names

    # Run: oord verify
    with pytest.raises(SystemExit) as ei_verify:
        oord_cli.main(["verify", str(bundle_path)])
    assert ei_verify.value.code == 0
    verify_out = capsys.readouterr().out
    assert "Bundle:" in verify_out
    assert "Hashes: OK" in verify_out
    assert re.search(r"TL:\s+OK", verify_out)
    assert re.search(r"JWKS:\s+OK", verify_out)
    assert verify_out.strip().endswith("OK")


def test_verify_detects_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    If bundle file contents are tampered, verify should fail with hashes_ok=False and exit code 1.
    """
    input_dir = _make_files(tmp_path)
    out_dir = tmp_path / "out"

    def fake_seal(
        base_url: str,
        api_key: str | None,
        org_id: str,
        batch_id: str,
        files: list[dict],
        tl_mode: str,
    ):
        root_cid = oord_cli._compute_merkle_root_from_manifest_files(files)
        manifest = {
            "manifest_version": "1.0",
            "org_id": org_id,
            "batch_id": batch_id,
            "created_at_ms": 0,
            "key_id": "stub-kid",
            "hash_alg": "sha256",
            "merkle": {
                "root_cid": root_cid,
                "tree_alg": "binary_merkle_sha256",
            },
            "files": files,
            "signature": "stub-signature",
        }
        tl_proof = {
            "tl_seq": 1,
            "merkle_root": root_cid,
            "sth_sig": "stub-sth-sig",
            "signer_key_id": "stub-kid",
        }
        return manifest, tl_proof


    def fake_jwks(base_url: str, api_key: str | None):
        return {
            "keys": [
                {
                    "kid": "stub-kid",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                }
            ]
        }

    monkeypatch.setattr(oord_cli, "_seal_via_core", fake_seal)
    monkeypatch.setattr(oord_cli, "_fetch_jwks_snapshot", fake_jwks)

    # Seal
    with pytest.raises(SystemExit) as ei_seal:
        oord_cli.main(
            [
                "seal",
                "--input-dir",
                str(input_dir),
                "--out",
                str(out_dir),
            ]
        )
    assert ei_seal.value.code == 0

    # Discover the sealed bundle by globbing the out_dir
    bundle_candidates = list(out_dir.glob("oord_bundle_*.zip"))
    assert bundle_candidates, "expected sealed bundle in out_dir"
    bundle_path = bundle_candidates[0]

    # Tamper: open zip and change one file
    tmp_zip = tmp_path / "tampered.zip"
    tmp_zip.write_bytes(bundle_path.read_bytes())
    with zipfile.ZipFile(tmp_zip, "a") as z:
        z.writestr("files/a.txt", b"tampered")

    # Verify should now fail with hash mismatch
    with pytest.raises(SystemExit) as ei_verify:
        oord_cli.main(["verify", str(tmp_zip)])
    assert ei_verify.value.code == 1
    ok, summary = oord_cli.verify_bundle(tmp_zip)
    assert ok is False
    assert summary["hashes_ok"] is False
    assert summary["hash_mismatches"]


def test_build_bundle_is_deterministic(tmp_path: Path) -> None:
    """
    Given the same manifest/tl_proof/jwks and input_dir, _build_bundle should
    produce byte-identical ZIPs across runs.
    """
    input_dir = _make_files(tmp_path)
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    files = oord_cli._collect_files_for_manifest(input_dir)
    root_cid = oord_cli._compute_merkle_root_from_manifest_files(files)

    manifest = {
        "manifest_version": "1.0",
        "org_id": "TEST-ORG",
        "batch_id": "BATCH-1",
        "created_at_ms": 0,
        "key_id": "stub-kid",
        "hash_alg": "sha256",
        "merkle": {
            "root_cid": root_cid,
            "tree_alg": "binary_merkle_sha256",
        },
        "files": files,
        "signature": "stub-signature",
    }
    tl_proof = {
        "tl_seq": 1,
        "merkle_root": manifest["merkle"]["root_cid"],
        "sth_sig": "stub-sth-sig",
        "signer_key_id": "stub-kid",
    }
    jwks = {
        "keys": [
            {
                "kid": "stub-kid",
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            }
        ]
    }

    bundle1 = oord_cli._build_bundle(manifest, tl_proof, jwks, input_dir, out1)
    bundle2 = oord_cli._build_bundle(manifest, tl_proof, jwks, input_dir, out2)

    assert bundle1.is_file()
    assert bundle2.is_file()

    data1 = bundle1.read_bytes()
    data2 = bundle2.read_bytes()

    # Full byte equality
    assert data1 == data2

    # And the hash is stable as a sanity check
    h1 = hashlib.sha256(data1).hexdigest()
    h2 = hashlib.sha256(data2).hexdigest()
    assert h1 == h2

    # Layout inside the deterministic bundle is also as expected
    with zipfile.ZipFile(bundle1, "r") as z:
        names = set(z.namelist())
        assert "manifest.json" in names
        assert "jwks_snapshot.json" in names
        assert "tl_proof.json" in names
        assert "files/a.txt" in names
        assert "files/sub/b.txt" in names


def test_verify_detects_merkle_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    If manifest.merkle.root_cid is inconsistent with the Merkle computed from
    manifest.files, verify should fail with a Merkle error and exit code 1.
    """
    input_dir = _make_files(tmp_path)
    out_dir = tmp_path / "out"

    def fake_seal(
        base_url: str,
        api_key: str | None,
        org_id: str,
        batch_id: str,
        files: list[dict],
        tl_mode: str,
    ):
        # Deliberately lie about the Merkle root while keeping files[]
        # consistent. This should trip the Merkle recomputation logic.
        wrong_root = "cid:sha256:" + "b" * 64
        manifest = {
            "manifest_version": "1.0",
            "org_id": org_id,
            "batch_id": batch_id,
            "created_at_ms": 0,
            "key_id": "stub-kid",
            "hash_alg": "sha256",
            "merkle": {
                "root_cid": wrong_root,
                "tree_alg": "binary_merkle_sha256",
            },
            "files": files,
            "signature": "stub-signature",
        }
        tl_proof = {
            "tl_seq": 1,
            "merkle_root": wrong_root,
            "sth_sig": "stub-sth-sig",
            "signer_key_id": "stub-kid",
        }
        return manifest, tl_proof

    def fake_jwks(base_url: str, api_key: str | None):
        return {
            "keys": [
                {
                    "kid": "stub-kid",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                }
            ]
        }

    monkeypatch.setattr(oord_cli, "_seal_via_core", fake_seal)
    monkeypatch.setattr(oord_cli, "_fetch_jwks_snapshot", fake_jwks)

    # Seal
    with pytest.raises(SystemExit) as ei_seal:
        oord_cli.main(
            [
                "seal",
                "--input-dir",
                str(input_dir),
                "--out",
                str(out_dir),
            ]
        )
    assert ei_seal.value.code == 0

    bundle_candidates = list(out_dir.glob("oord_bundle_*.zip"))
    assert bundle_candidates, "expected sealed bundle in out_dir"
    bundle_path = bundle_candidates[0]

    # Verify should now fail with a Merkle mismatch
    with pytest.raises(SystemExit) as ei_verify:
        oord_cli.main(["verify", str(bundle_path)])
    assert ei_verify.value.code == 1

    ok, summary = oord_cli.verify_bundle(bundle_path)
    assert ok is False
    assert summary["merkle"]["ok"] is False
    assert "recomputed Merkle root does not match" in (summary["merkle"]["error"] or "")
