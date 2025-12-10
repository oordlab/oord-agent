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
scripts/ctx.sh:33:  echo "## Grep (gateway/portal/merkle/signature)"
scripts/ctx.sh:43:     -e '@router\.|FastAPI\(|Pydantic|Schema|type ' \
scripts/ctx.sh:44:     -e 'Merkle|verify|sign|ed25519|sha256|reqwest|notify|Cargo\.toml' \
main.py:2:app = FastAPI()
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
docs/ADR-008-oord-seal-v1.md:67:- `merkle.root_cid` must match the Merkle root computed from `files[*].sha256` in a deterministic order (exact ordering rules are defined in the agent/CLI/bundle ADR).
docs/ADR-008-oord-seal-v1.md:68:- All `files[*].sha256` must be 64-char lowercase hex.
docs/ADR-008-oord-seal-v1.md:73:`proof.json` provides an optional Transparency Log anchoring proof for a manifest’s Merkle root.
docs/ADR-008-oord-seal-v1.md:79:- `merkle_root` — string; `"cid:sha256:<64hex>"`, must match `manifest.merkle.root_cid`.
docs/ADR-008-oord-seal-v1.md:82:  - `root_hash` — string; `"sha256:<64hex>"` Merkle root of the TL tree.
docs/ADR-008-oord-seal-v1.md:84:  - `key_id` — string; identifier of the Ed25519 key used to sign the STH.
docs/ADR-008-oord-seal-v1.md:85:  - `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the STH payload.
docs/ADR-008-oord-seal-v1.md:93:## 4. JSON Schemas
docs/ADR-008-oord-seal-v1.md:95:The following JSON Schemas are added under `oc/schemas/`:
docs/ADR-008-oord-seal-v1.md:108:## 5. Pydantic Models
docs/ADR-008-oord-seal-v1.md:110:To make these contracts easy to use inside the API service, we define Pydantic models under:
docs/ADR-008-oord-seal-v1.md:117:- `MerkleInfo`
docs/ADR-008-oord-seal-v1.md:124:- Mirror the JSON Schema shapes.
docs/ADR-008-oord-seal-v1.md:139:- Constructs example `SealManifest` and `TlProof` instances using Pydantic.
_ai/agent-context-index.md:34:## Grep (gateway/portal/merkle/signature)
tests/schemas/manifest_v1.json:14:    "signature"
tests/schemas/manifest_v1.json:27:      "description": "Hash algorithm used for per-file digests and Merkle leaves"
tests/schemas/manifest_v1.json:41:        "required": ["path", "sha256", "size_bytes"],
tests/schemas/manifest_v1.json:48:          "sha256": { "type": "string" },
tests/schemas/manifest_v1.json:53:    "signature": { "type": "string" },
tests/schemas/proof_v1.json:31:        "signature": {
tests/schemas/proof_v1.json:40:        "signature"
agent/receiver.py:87:def verify_bundle_via_cli(cfg: AgentConfig, bundle_path: Path) -> Tuple[int, str, str]:
agent/receiver.py:89:    Call the Oord CLI as a subprocess to verify a bundle.
agent/receiver.py:97:        "verify",
agent/receiver.py:146:            code, stdout, stderr = verify_bundle_via_cli(cfg, bundle_path)

## Recent Commits
- 7b71de9 Make oord seal deterministic and tighten bundle layout
- 6c2f506 CI: install pytest+pydantic directly, drop pip install .
- 5f53daa CI: install oord-agent via pyproject and drop Rust build
- 804b977 MVP-Phase1: Remove legacy gateway/Rust stack and finalize Python-only agent
- e97dd12 chore: establish seal/proof contracts and passing test baseline

## Timestamp
Generated: 2025-12-09 22:50:16Z (UTC)
