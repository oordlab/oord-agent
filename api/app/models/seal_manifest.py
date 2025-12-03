from __future__ import annotations

from typing import List, Optional, Literal

from pydantic import BaseModel, Field


class FileEntry(BaseModel):
    path: str = Field(..., description="Relative path inside the sealed bundle, e.g. 'files/report1.pdf'")
    sha256: str = Field(..., description="Hex-encoded SHA-256 digest of file contents")
    size_bytes: int = Field(..., ge=0, description="File size in bytes")


class MerkleInfo(BaseModel):
    root_cid: str = Field(
        ...,
        description="Content ID for Merkle root, e.g. 'cid:sha256:<hex>'",
    )
    tree_alg: Literal["binary_merkle_sha256"] = Field(
        "binary_merkle_sha256",
        description="Merkle tree algorithm identifier",
    )

class TlSth(BaseModel):
    tree_size: int
    root_hash: str
    timestamp_ms: int
    key_id: str
    signature: str


class TlProof(BaseModel):
    # Versioned proof contract so we can evolve fields later
    proof_version: str = Field(default="1.0")
    tl_seq: int
    merkle_root: str
    sth: TlSth

class SealManifest(BaseModel):
    """
    Canonical manifest for a sealed batch.

    Tests construct it like:

        SealManifest(
            org_id="DEMO-LABS",
            batch_id="BATCH-2025-0001",
            created_at_ms=1764350123456,
            key_id="org-DEMO-LABS-ed25519-1",
            merkle=MerkleInfo(...),
            files=[FileEntry(...)],
            signature="dummy-signature",
        )
    """

    # Default so tests don't have to pass it explicitly
    manifest_version: str = Field(
        default="1.0",
        description="Opaque manifest version string, e.g. '1.0'",
    )

    org_id: str = Field(
        ...,
        description="Originating org for this sealed batch, e.g. 'DEMO-LABS'",
    )
    batch_id: str = Field(
        ...,
        description="Caller-provided batch identifier, stable within the org",
    )
    created_at_ms: int = Field(
        ...,
        ge=0,
        description="Manifest creation time in milliseconds since epoch",
    )
    key_id: str = Field(
        ...,
        description="Key ID used to sign this manifest, e.g. 'org-DEMO-LABS-ed25519-1'",
    )

    hash_alg: Literal["sha256"] = Field(
        "sha256",
        description="Hash algorithm used for per-file digests and Merkle leaves",
    )

    merkle: MerkleInfo = Field(
        ...,
        description="Merkle tree summary for this batch",
    )

    files: List[FileEntry] = Field(
        default_factory=list,
        description="List of files included in this sealed batch",
    )

    signature: str = Field(
        ...,
        description="Detached signature over the canonical manifest payload",
    )

    tl_proof: Optional[TlProof] = Field(
        default=None,
        description="Optional TL anchoring proof for this seal",
    )


__all__ = [
    "FileEntry",
    "MerkleInfo",
    "SealManifest",
    "TlProof",
    "TlSth",
]
