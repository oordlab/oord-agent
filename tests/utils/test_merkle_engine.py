# oord-agent/tests/utils/test_merkle_engine.py
import json

import pytest

from cli import oord_cli


def test_cli_merkle_root_deterministic_ordering():
    files1 = [
        {"path": "files/a.txt", "sha256": "11" * 32, "size_bytes": 1},
        {"path": "files/b.txt", "sha256": "22" * 32, "size_bytes": 1},
        {"path": "files/c.txt", "sha256": "33" * 32, "size_bytes": 1},
    ]
    files2 = list(reversed(files1))

    root1 = oord_cli._compute_merkle_root_from_manifest_files(files1)
    root2 = oord_cli._compute_merkle_root_from_manifest_files(files2)

    assert root1 == root2
    assert root1.startswith("cid:sha256:")
    assert len(root1.split("cid:sha256:", 1)[1]) == 64


def test_cli_merkle_root_changes_when_hash_changes():
    base = [
        {"path": "files/a.txt", "sha256": "11" * 32, "size_bytes": 1},
        {"path": "files/b.txt", "sha256": "22" * 32, "size_bytes": 1},
    ]
    r1 = oord_cli._compute_merkle_root_from_manifest_files(base)

    mutated = [
        {"path": "files/a.txt", "sha256": "11" * 32, "size_bytes": 1},
        {"path": "files/b.txt", "sha256": "33" * 32, "size_bytes": 1},
    ]
    r2 = oord_cli._compute_merkle_root_from_manifest_files(mutated)

    assert r1 != r2


def test_manifest_unsigned_bytes_strips_signature_and_is_canonical():
    manifest = {
        "manifest_version": "1.0",
        "org_id": "DEMO-LABS",
        "batch_id": "BATCH-001",
        "created_at_ms": 1234567890,
        "key_id": "org-DEMO-LABS-ed25519-1",
        "hash_alg": "sha256",
        "merkle": {"root_cid": "cid:sha256:" + "a" * 64, "tree_alg": "binary_merkle_sha256"},
        "files": [],
        "signature": "dummy-signature",
    }

    b1 = oord_cli._manifest_unsigned_bytes(manifest)
    # signature must be removed
    obj = json.loads(b1.decode("utf-8"))
    assert "signature" not in obj

    # deterministic encoding: calling twice yields identical bytes
    b2 = oord_cli._manifest_unsigned_bytes(manifest)
    assert b1 == b2
