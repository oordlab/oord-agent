# Oord-Agent Context Index

## Directory Tree (trimmed)
.
├── _ai
│   └── agent-context-index.md
├── agent
│   ├── __init__.py
│   ├── config.py
│   ├── receiver.py
│   └── sender.py
├── api
│   ├── __init__.py
│   └── app
├── cli
│   └── oord_cli.py
├── docs
│   └── ADR-008-oord-seal-v1.md
├── main.py
├── Makefile
├── pyproject.toml
├── pytest.ini
├── scripts
│   └── ctx.sh
├── tests
│   ├── agent
│   ├── cli
│   ├── schemas
│   └── utils
└── utils

14 directories, 13 files

## Grep (gateway/portal/merkle/signature)
main.py:2:app = FastAPI()
scripts/ctx.sh:33:  echo "## Grep (gateway/portal/merkle/signature)"
scripts/ctx.sh:43:     -e '@router\.|FastAPI\(|Pydantic|Schema|type ' \
scripts/ctx.sh:44:     -e 'Merkle|verify|sign|ed25519|sha256|reqwest|notify|Cargo\.toml' \
api/app/models/seal_manifest.py:12:    sha256: str = Field(..., description="Hex-encoded SHA-256 digest of file contents")
api/app/models/seal_manifest.py:16:class MerkleInfo(BaseModel):
api/app/models/seal_manifest.py:19:        description="Content ID for Merkle root, e.g. 'cid:sha256:<hex>'",
api/app/models/seal_manifest.py:21:    tree_alg: Literal["binary_merkle_sha256"] = Field(
api/app/models/seal_manifest.py:22:        "binary_merkle_sha256",
api/app/models/seal_manifest.py:23:        description="Merkle tree algorithm identifier",
api/app/models/seal_manifest.py:38:    signer_key_id: Optional[str] = None
api/app/models/seal_manifest.py:51:            key_id="org-DEMO-LABS-ed25519-1",
api/app/models/seal_manifest.py:52:            merkle=MerkleInfo(...),
api/app/models/seal_manifest.py:54:            signature="dummy-signature",
api/app/models/seal_manifest.py:79:        description="Key ID used to sign this manifest, e.g. 'org-DEMO-LABS-ed25519-1'",
api/app/models/seal_manifest.py:82:    hash_alg: Literal["sha256"] = Field(
api/app/models/seal_manifest.py:83:        "sha256",
api/app/models/seal_manifest.py:84:        description="Hash algorithm used for per-file digests and Merkle leaves",
api/app/models/seal_manifest.py:87:    merkle: MerkleInfo = Field(
api/app/models/seal_manifest.py:89:        description="Merkle tree summary for this batch",
api/app/models/seal_manifest.py:97:    signature: str = Field(
api/app/models/seal_manifest.py:99:        description="Detached signature over the canonical manifest payload",
api/app/models/seal_manifest.py:102:    def unsigned_dict(self) -> dict:
api/app/models/seal_manifest.py:104:        Return the manifest as a plain dict without the signature field.
api/app/models/seal_manifest.py:106:        This is the view that is canonicalized and signed.
api/app/models/seal_manifest.py:109:        data.pop("signature", None)
api/app/models/seal_manifest.py:112:    def unsigned_bytes(self) -> bytes:
api/app/models/seal_manifest.py:114:        Return JCS-style canonical bytes for the unsigned manifest view.
api/app/models/seal_manifest.py:121:            self.unsigned_dict(),
api/app/models/seal_manifest.py:131:    "MerkleInfo",
docs/ADR-008-oord-seal-v1.md:17:- The reference CLI (`oord seal`, `oord verify`).
docs/ADR-008-oord-seal-v1.md:18:- Agents/watchers that build and verify sealed bundles.
docs/ADR-008-oord-seal-v1.md:32:- `key_id` — string; identifier of the Ed25519 key used to sign the manifest.
docs/ADR-008-oord-seal-v1.md:33:- `hash_alg` — string; currently `"sha256"`.
docs/ADR-008-oord-seal-v1.md:34:- `merkle` — object describing the Merkle tree:
docs/ADR-008-oord-seal-v1.md:35:  - `root_cid` — string; `"cid:sha256:<64hex>"`, derived from the Merkle root bytes.
docs/ADR-008-oord-seal-v1.md:36:  - `tree_alg` — string; `"binary_merkle_sha256"`.
docs/ADR-008-oord-seal-v1.md:39:  - `sha256` — string; 64-char lowercase hex SHA-256 digest of the file contents.
docs/ADR-008-oord-seal-v1.md:41:- `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the JCS-canonicalized manifest **without** the `signature` field.
docs/ADR-008-oord-seal-v1.md:47:1. Construct a manifest object containing all fields **except** `signature`.
docs/ADR-008-oord-seal-v1.md:50:4. Encode the raw 64-byte signature in URL-safe base64 without padding.
docs/ADR-008-oord-seal-v1.md:51:5. Insert this string into the `signature` field.
docs/ADR-008-oord-seal-v1.md:57:2. Extract and temporarily ignore `signature`.
docs/ADR-008-oord-seal-v1.md:59:4. Fetch the verifying key corresponding to `key_id` from JWKS.
docs/ADR-008-oord-seal-v1.md:60:5. Verify the Ed25519 signature over the canonical bytes.
docs/ADR-008-oord-seal-v1.md:61:6. Re-hash files, recompute Merkle root, and confirm it matches `merkle.root_cid`.
docs/ADR-008-oord-seal-v1.md:65:- `hash_alg` must be `"sha256"` in v1.
docs/ADR-008-oord-seal-v1.md:66:- `merkle.tree_alg` must be `"binary_merkle_sha256"` in v1.

## Recent Commits
- 137fc3a a bunch of stuff
- 7b71de9 Make oord seal deterministic and tighten bundle layout
- 6c2f506 CI: install pytest+pydantic directly, drop pip install .
- 5f53daa CI: install oord-agent via pyproject and drop Rust build
- 804b977 MVP-Phase1: Remove legacy gateway/Rust stack and finalize Python-only agent
- e97dd12 chore: establish seal/proof contracts and passing test baseline

## Timestamp
Generated: 2025-12-11 22:39:38Z (UTC)
