# Oord-Agent Context Index

## Directory Tree (trimmed)
.
├── _ai
│   ├── agent-context-index.md
│   └── ol-context-index.md
├── gateway
│   └── gateway
├── main.py
├── Makefile
├── pyproject.toml
├── pytest.ini
├── scripts
│   └── ctx.sh
├── tests
│   └── utils
└── utils
    ├── bundle_packer.py
    └── verify_bundle.py

8 directories, 9 files

## Grep (gateway/portal/merkle/signature)
gateway/gateway/src/pipeline.rs:34:    let sha = sha256_file(src)?;
gateway/gateway/src/pipeline.rs:137:    let sig = core_client::sign_session(&ctx, &sess.session_id)?;
gateway/gateway/src/pipeline.rs:192:        "signature": { "key_id": sig.kid, "algorithm": "Ed25519" },
gateway/gateway/src/pipeline.rs:215:        "bundle_sha256": session.bundle_sha256,
gateway/gateway/src/pipeline.rs:230:    // deterministic; in real-Core mode it reflects the current signing keys.
gateway/gateway/src/pipeline.rs:303:    println!("attestation_path={} sha256={}", out_pdf.display(), sha);
gateway/gateway/src/pipeline.rs:308:fn sha256_file(p: &Path) -> Result<String> {
gateway/gateway/src/main.rs:9:use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
gateway/gateway/src/main.rs:106:    // Core session + sign + TL submit
gateway/gateway/src/main.rs:108:    let _sig = core_client::sign_session(&ctx, &sess_resp.session_id)?;
gateway/gateway/src/main.rs:416:                        "bundle_sha256": sess.bundle_sha256,
gateway/gateway/src/main.rs:717:                println!("vault_loader_canonical_path={} sha256={}", out_path, digest);
gateway/gateway/src/main.rs:759:                println!("IQOQ_canonical_path={} sha256={}", out_path, digest);
gateway/gateway/src/main.rs:839:        let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
gateway/gateway/src/state.rs:14:    pub files: BTreeMap<String, Entry>,  // sha256 -> entry
gateway/gateway/Cargo.toml:15:reqwest = { version = "0.12", default-features = false, features = ["blocking", "json", "multipart", "rustls-tls"] }
gateway/gateway/Cargo.toml:18:notify = "6"
gateway/gateway/src/core_client.rs:3:use reqwest::blocking::{Client, multipart};
gateway/gateway/src/core_client.rs:4:use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT, AUTHORIZATION};
gateway/gateway/src/core_client.rs:36:fn is_5xx(status: reqwest::StatusCode) -> bool {
gateway/gateway/src/core_client.rs:42:    if !mr.starts_with("cid:sha256:") || mr.len() < "cid:sha256:".len() + 8 {
gateway/gateway/src/core_client.rs:43:        return Err(anyhow!("invalid merkle_root format (expected cid:sha256:<hex>)"));
gateway/gateway/src/core_client.rs:72:    pub signature: String,
gateway/gateway/src/core_client.rs:73:    pub t_signed_ms: i64,
gateway/gateway/src/core_client.rs:109:        "signature": { "key_id": "dev-kid-stub", "algorithm": "Ed25519" },
gateway/gateway/src/core_client.rs:162:        return Ok(IngestResp { unit_cid: format!("cid:sha256:stub_{name}") });
gateway/gateway/src/core_client.rs:192:        let root = format!("cid:sha256:stub_{:02}", unit_cids.len());
gateway/gateway/src/core_client.rs:205:pub fn sign_session(ctx: &CoreCtx, session_id: &str) -> Result<SignResp> {
gateway/gateway/src/core_client.rs:207:        return Ok(SignResp { kid: "stub-kid".into(), signature: "stub-signature".into(), t_signed_ms: Utc::now().timestamp_millis() });
gateway/gateway/src/core_client.rs:210:    let url = format!("{}/v1/session/sign", ctx.base_url);
gateway/gateway/src/core_client.rs:219:/// Submit a Merkle root to Core TL: POST /v1/tl/submit
gateway/gateway/src/core_client.rs:268:// (Optional) Legacy type retained only if callers still deserialize it somewhere
gateway/gateway/src/core_client.rs:276:pub fn commit_tl(_ctx: &CoreCtx, _session_id: &str, _signature: &str) -> Result<CommitResp> {
Makefile:4:	cargo build --manifest-path gateway/Cargo.toml
Makefile:10:	cargo test --manifest-path gateway/Cargo.toml
main.py:2:app = FastAPI()
gateway/gateway/src/sessions_db.rs:24:    pub bundle_sha256: Option<String>,
gateway/gateway/src/sessions_db.rs:34:    pub sha256: String,
gateway/gateway/src/sessions_db.rs:79:            bundle_sha256   TEXT
gateway/gateway/src/sessions_db.rs:88:            sha256          TEXT NOT NULL,
gateway/gateway/src/sessions_db.rs:89:            content_type    TEXT,
gateway/gateway/src/sessions_db.rs:104:        CREATE INDEX IF NOT EXISTS idx_files_sha256
gateway/gateway/src/sessions_db.rs:105:            ON files (sha256);
gateway/gateway/src/sessions_db.rs:107:        CREATE UNIQUE INDEX IF NOT EXISTS idx_files_session_sha256
gateway/gateway/src/sessions_db.rs:108:            ON files (session_id, sha256);
gateway/gateway/src/sessions_db.rs:129:        bundle_sha256: row.get(11)?,
gateway/gateway/src/sessions_db.rs:140:        sha256: row.get(5)?,
gateway/gateway/src/sessions_db.rs:194:                bundle_sha256

## Recent Commits

## Timestamp
Generated: 2025-12-02 12:20:57Z (UTC)
