# oord-agent/api/app/models/seal_manifest.py
from __future__ import annotations

from typing import List, Optional, Literal, Any
import json

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

class TlProof(BaseModel):
    """
    Canonical TL proof shape shared with:
      - /v1/seal TL info (Core)
      - schemas/proof_v1.json
      - tl_proof.json in bundles
    """
    proof_version: str = "1.0"
    tl_seq: int
    merkle_root: str
    sth_sig: str
    t_log_ms: int
    signer_key_id: Optional[str] = None


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
    
    def unsigned_dict(self) -> dict:
        """
        Return the manifest as a plain dict without the signature field.

        This is the view that is canonicalized and signed.
        """
        data: dict = self.model_dump()
        data.pop("signature", None)
        return data

    def unsigned_bytes(self) -> bytes:
        """
        Return JCS-style canonical bytes for the unsigned manifest view.

        For our restricted manifest domain (strings, ints, arrays, objects,
        no floats), json.dumps with sort_keys + tight separators matches
        the RFC 8785 behavior we care about.
        """
        return json.dumps(
            self.unsigned_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")



__all__ = [
    "FileEntry",
    "MerkleInfo",
    "SealManifest",
    "TlProof",
]
