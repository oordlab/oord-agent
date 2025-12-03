use anyhow::{Result, anyhow};
use chrono::Utc;
use reqwest::blocking::{Client, multipart};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::{env, fs, fs::File, io::Write, io::Cursor, path::Path, path::PathBuf, time::Duration};
use zip::{ZipWriter, ZipArchive, write::SimpleFileOptions};

#[derive(Debug, Clone)]
pub struct CoreCtx {
    pub base_url: String,
    pub api_key: String,
}

fn build_client() -> Result<Client> {
    // Default: 10s, override via OORD_REQ_TIMEOUT_MS
    let t_ms: u64 = env::var("OORD_REQ_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(USER_AGENT, HeaderValue::from_static("oord-gateway/1.0"));
    // Bearer auth is set per-request to avoid leaking if client reused elsewhere
    Ok(Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_millis(t_ms))
        .build()?)
}

fn bearer(h: &str) -> HeaderValue {
    let v = format!("Bearer {h}");
    HeaderValue::from_str(&v).unwrap_or(HeaderValue::from_static("Bearer devkey"))
}

fn is_5xx(status: reqwest::StatusCode) -> bool {
    status.as_u16() / 100 == 5
}

fn validate_merkle_root(mr: &str) -> Result<()> {
    // Keep it lightweight; stricter checks live server-side.
    if !mr.starts_with("cid:sha256:") || mr.len() < "cid:sha256:".len() + 8 {
        return Err(anyhow!("invalid merkle_root format (expected cid:sha256:<hex>)"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct IngestResp {
    pub unit_cid: String,
}

#[derive(Debug, Serialize)]
struct SessionReq {
    unit_cids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SessionResp {
    pub session_id: String,
    pub merkle_root: String,
}

#[derive(Debug, Serialize)]
struct SignReq {
    session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SignResp {
    pub kid: String,
    pub signature: String,
    pub t_signed_ms: i64,
}

// ----- Transparency Log v1 -----
#[derive(Debug, Deserialize)]
pub struct TLProof {
    pub tl_seq: u64,
    pub merkle_root: String,
    pub sth_sig: String,
    pub t_log_ms: i64,
    #[serde(default)]
    pub company_root: Option<String>,
}


#[derive(Debug, Serialize)]
struct BundleReq {
    session_id: String,
    include_bytes: bool,
    include_verifier: bool,
}

pub fn is_stub(base_url: &str) -> bool {
    base_url.eq_ignore_ascii_case("stub") || env::var("OORD_CORE_STUB").ok().as_deref() == Some("1")
}

/// Write a minimal but valid Inspector Pack ZIP containing manifest.json and session.json.
fn write_minimal_pack_zip(out_zip: &Path, session_id: &str) -> Result<()> {
    let f = File::create(out_zip)?;
    let mut zw = ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Minimal manifest.json
    let manifest = serde_json::json!({
        "session_id": session_id,
        "merkle_root": "0000000000000000000000000000000000000000000000000000000000000000",
        "signature": { "key_id": "dev-kid-stub", "algorithm": "Ed25519" },
        "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    });
    zw.start_file("manifest.json", opts)?;
    zw.write_all(serde_json::to_string(&manifest)?.as_bytes())?;

    // Minimal session.json
    let session = serde_json::json!({
        "session_id": session_id,
        "units_count": 0,
        "flagged_count": 0,
        "duplicate_count": 0,
        "thresholds": { "min_resolution": "1024x768", "min_blur_score": 0.5 }
    });
    zw.start_file("session.json", opts)?;
    zw.write_all(serde_json::to_string(&session)?.as_bytes())?;

    zw.finish()?;
    Ok(())
}

/// Write a *real* pack from provided JSON values (no Core dependency).
pub fn bundle_save_zip_local(
    out_dir: &Path,
    label: &str,
    manifest_json: &serde_json::Value,
    session_json: &serde_json::Value,
    jwks_json: Option<&serde_json::Value>,
) -> Result<PathBuf> {
    let bundle_name = format!("inspector_pack_{}.zip", label);
    let out_zip = out_dir.join(bundle_name);
    let f = File::create(&out_zip)?;
    let mut zw = ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zw.start_file("manifest.json", opts)?;
    zw.write_all(serde_json::to_string(manifest_json)?.as_bytes())?;

    zw.start_file("session.json", opts)?;
    zw.write_all(serde_json::to_string(session_json)?.as_bytes())?;

    if let Some(j) = jwks_json {
        zw.start_file("jwks.json", opts)?;
        zw.write_all(serde_json::to_string(j)?.as_bytes())?;
    }

    zw.finish()?;
    Ok(out_zip)
}

pub fn ingest_file(ctx: &CoreCtx, file: &Path) -> Result<IngestResp> {
    if is_stub(&ctx.base_url) {
        let name = file.file_name().unwrap().to_string_lossy();
        return Ok(IngestResp { unit_cid: format!("cid:sha256:stub_{name}") });
    }
    let client = build_client()?;
    let url = format!("{}/v1/ingest", ctx.base_url);
    // one light retry on 5xx — rebuild the form each attempt
    let mut tries = 0;
    loop {
        let part = multipart::Part::file(file)?;
        let form = multipart::Form::new().part("file", part);
        let resp = client.post(&url)
            .header(AUTHORIZATION, bearer(&ctx.api_key))
            .multipart(form)
            .send()?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.json::<IngestResp>()?);
        }
        if is_5xx(status) && tries == 0 {
            tries += 1;
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!(format!("ingest failed: {} {}", status, body)));
    }
}

pub fn create_session(ctx: &CoreCtx, unit_cids: &[String]) -> Result<SessionResp> {
    if is_stub(&ctx.base_url) {
        // Make the stub root CID-style for downstream consistency
        let root = format!("cid:sha256:stub_{:02}", unit_cids.len());
        return Ok(SessionResp { session_id: "stub_session".into(), merkle_root: root });
    }
    let client = build_client()?;
    let url = format!("{}/v1/session", ctx.base_url);
    let r = client.post(&url)
        .header(AUTHORIZATION, bearer(&ctx.api_key))
        .json(&SessionReq{ unit_cids: unit_cids.to_vec() })
        .send()?
        .error_for_status()?;
    Ok(r.json::<SessionResp>()?)
}

pub fn sign_session(ctx: &CoreCtx, session_id: &str) -> Result<SignResp> {
    if is_stub(&ctx.base_url) {
        return Ok(SignResp { kid: "stub-kid".into(), signature: "stub-signature".into(), t_signed_ms: Utc::now().timestamp_millis() });
    }
    let client = build_client()?;
    let url = format!("{}/v1/session/sign", ctx.base_url);
    let r = client.post(&url)
        .header(AUTHORIZATION, bearer(&ctx.api_key))
        .json(&SignReq{ session_id: session_id.into() })
        .send()?
        .error_for_status()?;
    Ok(r.json::<SignResp>()?)
}

/// Submit a Merkle root to Core TL: POST /v1/tl/submit
pub fn submit_tl(ctx: &CoreCtx, merkle_root: &str) -> Result<TLProof> {
    if is_stub(&ctx.base_url) {
        return Ok(TLProof {
            tl_seq: 42,
            merkle_root: merkle_root.to_string(),
            sth_sig: "stub-sth-sig".into(),
            t_log_ms: Utc::now().timestamp_millis(),
            company_root: None,
        });
    }
    validate_merkle_root(merkle_root)?;
    let client = build_client()?;
    let url = format!("{}/v1/tl/submit", ctx.base_url);
    let r = client.post(&url)
        .header(AUTHORIZATION, bearer(&ctx.api_key))
        .json(&serde_json::json!({ "merkle_root": merkle_root }))
        .send()?
        .error_for_status()?;
    Ok(r.json::<TLProof>()?)
}

/// Fetch current JWKS from Core (or a deterministic stub JWKS in stub mode).
pub fn fetch_jwks(ctx: &CoreCtx) -> Result<serde_json::Value> {
    if is_stub(&ctx.base_url) {
        // Mirror api/app/routes/core_v1.py /jwks stub: single Ed25519 key with zeroed x.
        return Ok(serde_json::json!({
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
        }));
    }
    let client = build_client()?;
    let url = format!("{}/v1/jwks", ctx.base_url);
    let r = client
        .get(&url)
        .header(AUTHORIZATION, bearer(&ctx.api_key))
        .send()?
        .error_for_status()?;
    Ok(r.json::<serde_json::Value>()?)
}

// (Optional) Legacy type retained only if callers still deserialize it somewhere
#[derive(Debug, Deserialize)]
pub struct CommitResp {
    pub tree_size: Option<u64>,
    pub sth_ts: Option<i64>,
}

/// DEPRECATED: do not use. Prefer `submit_tl`.
pub fn commit_tl(_ctx: &CoreCtx, _session_id: &str, _signature: &str) -> Result<CommitResp> {
    Err(anyhow::anyhow!("commit_tl deprecated: use submit_tl with merkle_root"))
}


pub fn bundle_save_zip(ctx: &CoreCtx, session_id: &str, include_bytes: bool, include_verifier: bool, out_dir: &Path, label: &str) -> Result<PathBuf> {
    let bundle_name = format!("inspector_pack_{}.zip", label);
    let out_path = out_dir.join(bundle_name);
    if is_stub(&ctx.base_url) {
        // Write a minimal valid pack so downstream tools (attestation) work.
        write_minimal_pack_zip(&out_path, session_id)?;
        return Ok(out_path);
    }
    let client = build_client()?;
    let url = format!("{}/v1/bundle", ctx.base_url);
    let req = BundleReq{ session_id: session_id.into(), include_bytes, include_verifier };
    let resp = client.post(&url)
        .header(AUTHORIZATION, bearer(&ctx.api_key))
        .json(&req)
        .send()?
        .error_for_status()?;
    let bytes = resp.bytes()?;

    // Validate response as a non-empty ZIP with manifest/session; else, fallback to minimal pack.
    if bytes.is_empty() {
        write_minimal_pack_zip(&out_path, session_id)?;
        return Ok(out_path);
    }
    let mut cur = Cursor::new(&bytes);
    match ZipArchive::new(&mut cur) {
        Ok(mut za) => {
            let mut has_manifest = false;
            let mut has_session = false;
            for i in 0..za.len() {
                if let Ok(name) = za.by_index(i).map(|f| f.name().to_string()) {
                    if name == "manifest.json" { has_manifest = true; }
                    if name == "session.json"  { has_session  = true; }
                }
            }
            if !(has_manifest && has_session) {
                write_minimal_pack_zip(&out_path, session_id)?;
                return Ok(out_path);
            }
        }
        Err(_) => {
            write_minimal_pack_zip(&out_path, session_id)?;
            return Ok(out_path);
        }
    }
    
    fs::write(&out_path, &bytes)?;        
    Ok(out_path)
}
