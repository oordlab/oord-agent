# ADR-008 — Oord Seal v1 Manifest & Proof Contracts

**Status:** Accepted  
**Date:** 2025-12-02  
**Owners:** Oord-Core  

## 1. Summary

This ADR defines the canonical contracts for:

- `manifest.json` — **Oord Seal v1 manifest** for a sealed batch of files.
- `proof.json` — **Oord TL proof v1** for anchoring a sealed batch into the Transparency Log (TL).

These JSON formats are used by:

- Oord-Core HTTP APIs (`/v1/seal`, TL endpoints).
- The reference CLI (`oord seal`, `oord verify`).
- Agents/watchers that build and verify sealed bundles.

No domain-specific fields (lab, finance, etc.) are allowed in these contracts.

## 2. Manifest v1 — Fields & Semantics

### 2.1 Top-level structure

`manifest.json` is a single JSON object with the following fields:

- `manifest_version` — string, currently `"1.0"`.
- `org_id` — string; caller-supplied organization identifier.
- `batch_id` — string; caller-supplied batch identifier (unique per org in caller’s domain).
- `created_at_ms` — integer; UNIX epoch milliseconds from the sender’s clock (informational).
- `key_id` — string; identifier of the Ed25519 key used to sign the manifest.
- `hash_alg` — string; currently `"sha256"`.
- `merkle` — object describing the Merkle tree:
  - `root_cid` — string; `"cid:sha256:<64hex>"`, derived from the Merkle root bytes.
  - `tree_alg` — string; `"binary_merkle_sha256"`.
- `files` — array of file entries:
  - `path` — string; relative path inside `files/` within the bundle.
  - `sha256` — string; 64-char lowercase hex SHA-256 digest of the file contents.
  - `size_bytes` — integer; file size in bytes.
- `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the JCS-canonicalized manifest **without** the `signature` field.

No other top-level fields are allowed.

### 2.2 Signing rules (JCS + Ed25519)

1. Construct a manifest object containing all fields **except** `signature`.
2. Canonicalize this object using RFC 8785 **JCS** (JSON Canonicalization Scheme).
3. Sign the resulting canonical byte sequence with an Ed25519 private key.
4. Encode the raw 64-byte signature in URL-safe base64 without padding.
5. Insert this string into the `signature` field.
6. Emit `manifest.json` as standard UTF-8 JSON.

Verification:

1. Parse `manifest.json`.
2. Extract and temporarily ignore `signature`.
3. Canonicalize the remaining object with JCS.
4. Fetch the verifying key corresponding to `key_id` from JWKS.
5. Verify the Ed25519 signature over the canonical bytes.
6. Re-hash files, recompute Merkle root, and confirm it matches `merkle.root_cid`.

### 2.3 Invariants

- `hash_alg` must be `"sha256"` in v1.
- `merkle.tree_alg` must be `"binary_merkle_sha256"` in v1.
- `merkle.root_cid` must match the Merkle root computed from `files[*].sha256` in a deterministic order (exact ordering rules are defined in the agent/CLI/bundle ADR).
- All `files[*].sha256` must be 64-char lowercase hex.
- `files[*].path` values define the layout under `files/` in the bundle and must be unique within a manifest.

## 3. TL Proof v1 — Fields & Semantics

`proof.json` provides an optional Transparency Log anchoring proof for a manifest’s Merkle root.

Top-level fields:

- `proof_version` — string; `"1.0"`.
- `tl_seq` — integer; TL sequence number at which this root was committed.
- `merkle_root` — string; `"cid:sha256:<64hex>"`, must match `manifest.merkle.root_cid`.
- `sth` — object describing the Signed Tree Head (STH) for the TL:
  - `tree_size` — integer; TL tree size at the time of this STH.
  - `root_hash` — string; `"sha256:<64hex>"` Merkle root of the TL tree.
  - `timestamp_ms` — integer; UNIX epoch milliseconds from the TL’s clock.
  - `key_id` — string; identifier of the Ed25519 key used to sign the STH.
  - `signature` — string; URL-safe base64 (no padding) Ed25519 signature over the STH payload.

Semantics:

- `tl_seq` is the entry sequence for this `merkle_root` in `_data/tl.db`.
- `merkle_root` is the same value as `manifest.merkle.root_cid`.
- `sth` can be verified using the TL JWKS; the exact STH payload format is defined in the TL ADR (ADR-007).

## 4. JSON Schemas

The following JSON Schemas are added under `oc/schemas/`:

- `oc/schemas/manifest_v1.json` — “Oord Seal Manifest v1”.
- `oc/schemas/proof_v1.json` — “Oord TL Proof v1”.

These schemas:

- Forbid additional properties.
- Enforce value shapes (types, regex patterns, enums).
- Are the source of truth for integration with non-Python clients.

Core may optionally expose these schemas over HTTP in the future (e.g. `/v1/schemas/manifest_v1`).

## 5. Pydantic Models

To make these contracts easy to use inside the API service, we define Pydantic models under:

- `oc/api/app/models/seal_manifest.py`

Models:

- `FileEntry`
- `MerkleInfo`
- `SealManifest`
- `TlSth`
- `TlProof`

These models:

- Mirror the JSON Schema shapes.
- Forbid extra fields (`extra = "forbid"`).
- Are used by `/v1/seal` (request/response) and, where appropriate, TL APIs.

## 6. Backwards Compatibility

This ADR supersedes any prior “Inspector Pack” manifest definitions. Legacy artifacts and schemas are archived under `_archive/` and are **not** considered part of the post-pivot contract surface.

There is no attempt to auto-migrate old manifests to v1; they are treated as separate formats.

## 7. Testing

We add a basic contract test that:

- Loads `manifest_v1.json` and `proof_v1.json` from `oc/schemas/`.
- Constructs example `SealManifest` and `TlProof` instances using Pydantic.
- Asserts that:
  - Required fields are present.
  - Canonical shapes (patterns, enums) match expectations.
  - Example values round-trip through the models without mutation.

These tests live under `oc/tests/test_seal_contracts.py` and are executed via `pytest` (see repo test docs).
