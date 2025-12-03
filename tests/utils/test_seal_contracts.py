import json
from pathlib import Path

from api.app.models.seal_manifest import FileEntry, MerkleInfo, SealManifest, TlProof, TlSth


BASE_DIR = Path(__file__).resolve().parents[1]


def test_manifest_schema_file_exists_and_has_core_fields():
    schema_path = BASE_DIR / "schemas" / "manifest_v1.json"
    assert schema_path.is_file(), "schemas/manifest_v1.json missing"

    data = json.loads(schema_path.read_text())
    for field in [
        "manifest_version",
        "org_id",
        "batch_id",
        "created_at_ms",
        "key_id",
        "hash_alg",
        "merkle",
        "files",
        "signature",
    ]:
        assert field in data["properties"]


def test_proof_schema_file_exists_and_has_core_fields():
    schema_path = BASE_DIR / "schemas" / "proof_v1.json"
    assert schema_path.is_file(), "schemas/proof_v1.json missing"

    data = json.loads(schema_path.read_text())
    for field in ["proof_version", "tl_seq", "merkle_root", "sth"]:
        assert field in data["properties"]


def test_pydantic_manifest_roundtrip_example():
    manifest = SealManifest(
        org_id="DEMO-LABS",
        batch_id="BATCH-2025-0001",
        created_at_ms=1764350123456,
        key_id="org-DEMO-LABS-ed25519-1",
        merkle=MerkleInfo(
            root_cid="cid:sha256:" + "a" * 64,
        ),
        files=[
            FileEntry(
                path="files/report1.pdf",
                sha256="b" * 64,
                size_bytes=12345,
            )
        ],
        signature="dummy-signature",
    )

    dumped = manifest.model_dump()
    assert dumped["manifest_version"] == "1.0"
    assert dumped["hash_alg"] == "sha256"
    assert dumped["merkle"]["root_cid"].startswith("cid:sha256:")


def test_pydantic_proof_roundtrip_example():
    proof = TlProof(
        tl_seq=42,
        merkle_root="cid:sha256:" + "c" * 64,
        sth=TlSth(
            tree_size=42,
            root_hash="sha256:" + "d" * 64,
            timestamp_ms=1764350123456,
            key_id="tl-ed25519-1",
            signature="dummy-sth-signature",
        ),
    )

    dumped = proof.model_dump()
    assert dumped["proof_version"] == "1.0"
    assert dumped["sth"]["tree_size"] == 42
