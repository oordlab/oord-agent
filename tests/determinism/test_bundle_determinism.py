import hashlib
import os
import shutil
from pathlib import Path

import pytest

from cli import oord_cli


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _prepare_input_tree(tmp_path: Path) -> tuple[Path, list[dict]]:
    """
    Copy the determinism fixture tree into a temp dir and build manifest-style
    file metadata (path, sha256, size_bytes) for it.
    """
    fixture_root = (
        Path(__file__).parent.parent / "fixtures" / "determinism" / "input"
    ).resolve()
    if not fixture_root.is_dir():
        raise RuntimeError(f"determinism fixture tree missing: {fixture_root}")

    input_dir = tmp_path / "input"
    shutil.copytree(fixture_root, input_dir)

    files_meta: list[dict] = []
    for p in sorted(input_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(input_dir)
        manifest_path = "files/" + str(rel).replace(os.sep, "/")
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        size_bytes = p.stat().st_size
        files_meta.append(
            {
                "path": manifest_path,
                "sha256": digest,
                "size_bytes": size_bytes,
            }
        )
    return input_dir, files_meta


def _make_stub_manifest_and_proof(files_meta: list[dict]) -> tuple[dict, dict, dict]:
    """
    Build a stable manifest, TL proof, and JWKS snapshot suitable for
    feeding into the CLI's seal path via a monkeypatched _seal_via_core.
    """
    merkle_root = oord_cli._compute_merkle_root_from_manifest_files(files_meta)

    manifest: dict = {
        "manifest_version": "1.0",
        "org_id": "DETERMINISM-ORG",
        "batch_id": "DET-001",
        "created_at_ms": 0,
        "key_id": "stub-kid",
        "hash_alg": "sha256",
        "merkle": {
            "root_cid": merkle_root,
            "tree_alg": "binary_merkle_sha256",
        },
        "files": files_meta,
        # signature value is irrelevant for determinism; bundle packer just
        # treats it as data.
        "signature": "stub-signature",
    }

    tl_proof: dict = {
        "proof_version": "1.0",
        "tl_seq": 1,
        "merkle_root": merkle_root,
        "sth_sig": "stub-sth-sig",
        "t_log_ms": 0,
        "signer_key_id": "stub-kid",
    }

    jwks: dict = {
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

    return manifest, tl_proof, jwks


@pytest.mark.parametrize("run_idx", [1, 2])
def test_bundle_determinism_two_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_idx: int) -> None:
    """
    Seal the same input tree twice via oord_cli.main("seal", ...) with a
    stubbed _seal_via_core, and assert the resulting bundle bytes are identical.

    We parameterize the test to force pytest to run the same logic twice in a
    fresh tmp_path; the SHA comparison is done at the end using a shared
    file storing the first hash.
    """
    input_dir, files_meta = _prepare_input_tree(tmp_path)
    manifest, tl_proof, jwks = _make_stub_manifest_and_proof(files_meta)

    def fake_seal_via_core(*args, **kwargs):
        # Match the real contract: (manifest, tl_proof)
        # Determinism test is about bundle packing, not Core behavior.
        return manifest, tl_proof

    monkeypatch.setattr(oord_cli, "_seal_via_core", fake_seal_via_core)

    # If the CLI has a JWKS fetch helper, stub it so we don't hit the network
    # and we get a stable jwks_snapshot.json in the bundle.
    if hasattr(oord_cli, "_fetch_jwks_snapshot"):
        def fake_fetch_jwks_snapshot(*args, **kwargs):
            return jwks

        monkeypatch.setattr(oord_cli, "_fetch_jwks_snapshot", fake_fetch_jwks_snapshot)

    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run the real CLI entrypoint; it will call sys.exit.
    args = [
        "seal",
        "--input-dir",
        str(input_dir),
        "--out",
        str(out_dir),
        "--core-url",
        "http://stub-core",
        "--org-id",
        "DETERMINISM-ORG",
        "--batch-id",
        f"DET-{run_idx}",
    ]

    with pytest.raises(SystemExit) as ei:
        oord_cli.main(args)
    assert ei.value.code == 0

    bundles = sorted(out_dir.glob("oord_bundle_*.zip"))
    assert len(bundles) == 1, f"expected exactly one bundle, got {bundles}"
    bundle_path = bundles[0]
    sha = _compute_sha256(bundle_path)

    # Write/read a shared hash in /tmp so both param runs can compare.
    shared_hash_path = Path("/tmp/oord-agent-determinism-sha.txt")

    if run_idx == 1:
        shared_hash_path.write_text(sha, encoding="utf-8")
    else:
        first = shared_hash_path.read_text(encoding="utf-8").strip()
        if first != sha:
            pytest.fail(
                f"bundle determinism failed: first={first} second={sha}",
                pytrace=True,
            )
