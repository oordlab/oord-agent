// gateway/src/pipeline.rs
use crate::config::Cfg;
use crate::state;
use crate::core_client;
use crate::sessions_db;
use anyhow::{Result, anyhow, Context};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use chrono::{Local, Utc};
use serde_json::json;
use std::fs;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::process::Command;

const DEFAULT_COMPANY_ID: &str = "PILOT-LAB";

fn data_root_from_out_dir(out_dir: &str) -> PathBuf {
    let p = PathBuf::from(out_dir);
    match p.parent() {
        Some(parent) => parent.join("_data"),
        None => PathBuf::from("gateway/_data"),
    }
}

fn ensure_data_dirs(data_root: &Path) -> Result<()> {
    fs::create_dir_all(data_root.join("uploads"))?;
    fs::create_dir_all(data_root.join("bundles"))?;
    Ok(())
}

fn store_and_hash_file(src: &Path, uploads_root: &Path, session_id: i64) -> Result<(PathBuf, String, u64)> {
    let sha = sha256_file(src)?;
    let filename = src
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("file");
    let sess_dir = uploads_root.join(session_id.to_string());
    fs::create_dir_all(&sess_dir)?;
    let dest_name = format!("{}-{}", &sha[..12], filename);
    let dest_path = sess_dir.join(dest_name);
    if !dest_path.exists() {
        fs::copy(src, &dest_path)?;
    }
    let meta = fs::metadata(&dest_path)?;
    Ok((dest_path, sha, meta.len()))
}

pub fn list_input_files(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for entry in WalkDir::new(dir).max_depth(1).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() {
            if let Some(ext) = p.extension().and_then(OsStr::to_str) {
                let ext_lower = ext.to_ascii_lowercase();
                if ["pdf", "csv", "txt"].contains(&ext_lower.as_str()) {
                    v.push(p.to_path_buf());
                }
            }
        }
    }
    v.sort();
    v
}

pub fn on_new_files(files: Vec<PathBuf>, cfg: &Cfg) -> Result<PathBuf> {
    if files.is_empty() {
        return Err(anyhow!("no input files found"));
    }

    let resolved_label = resolve_batch_label(&cfg.watcher.batch_label, &cfg.lab.study_id);

    let ctx = core_client::CoreCtx {
        base_url: cfg.core.base_url.clone(),
        api_key: cfg.core.api_key.clone(),
    };

    let out_dir = PathBuf::from(&cfg.watcher.out_dir);
    fs::create_dir_all(&out_dir)?;
    let state_path = out_dir.join("state.json");
    eprintln!("state_path={}", state_path.display());
    let mut st = state::load(&state_path);

    // Files live under data_root (…/gateway/_data), DB base_dir is the parent (…/gateway)
    let data_root = data_root_from_out_dir(&cfg.watcher.out_dir);
    ensure_data_dirs(&data_root)?;
    let db_base = data_root
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("gateway"));

    sessions_db::init_db(&db_base)?;

    let session = sessions_db::create_session(
        &db_base,
        &resolved_label,
        DEFAULT_COMPANY_ID,
        Some(&resolved_label),
    )?;


    let uploads_root = data_root.join("uploads");
    // let now_ms = Utc::now().timestamp_millis();

    let mut fresh: Vec<(PathBuf, String)> = Vec::new();
    for f in &files {
        let (stored_path, sha, size_bytes) = store_and_hash_file(f, &uploads_root, session.id)?;
        if !state::is_seen(&st, &sha) {
            sessions_db::insert_or_get_file(
                &db_base,
                session.id,
                f.file_name().and_then(OsStr::to_str).unwrap_or("file"),
                &stored_path,
                size_bytes,
                &sha,
                None,
                "source",
            )?;              
            fresh.push((stored_path.clone(), sha));
        } else {
            eprintln!("skip: already processed {}", f.display());
        }
    }
    if fresh.is_empty() {
        return Err(anyhow!("no new files to process (all were cached)"));
    }

    let mut unit_cids = Vec::with_capacity(fresh.len());
    for (f, _) in &fresh {
        let r = core_client::ingest_file(&ctx, f)?;
        unit_cids.push(r.unit_cid);
    }

    let sess = core_client::create_session(&ctx, &unit_cids)?;

    let sig = core_client::sign_session(&ctx, &sess.session_id)?;

    let tl_proof_path = out_dir.join("tl_proof.json");
    let tl_block_json = match core_client::submit_tl(&ctx, &sess.merkle_root) {
        Ok(proof) => {
            let tl_seq = proof.tl_seq;
            let mr = proof.merkle_root.clone();
            let sth = proof.sth_sig.clone();
            fs::write(
                &tl_proof_path,
                serde_json::to_string_pretty(&json!({
                    "tl_seq": tl_seq,
                    "merkle_root": mr,
                    "sth_sig": sth,
                    "t_log_ms": proof.t_log_ms
                }))?,
            )?;
            eprintln!("   │ tl_proof: {}", tl_proof_path.display());
            json!({
                "tl_seq": tl_seq,
                "merkle_root": mr,
                "sth_sig": sth,
                "t_log_ms": proof.t_log_ms
            })
        }
        Err(err) => {
            let now_ms = Utc::now().timestamp_millis();
            let sentinel = json!({
                "status": "unavailable",
                "merkle_root": sess.merkle_root,
                "error": err.to_string(),
                "t_ms": now_ms
            });
            fs::write(&tl_proof_path, serde_json::to_string_pretty(&sentinel)?)?;
            eprintln!("   │ tl_proof (unavailable): {}", tl_proof_path.display());
            sentinel
        }
    };

    let ts_iso = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        //
    // ★ NEW: Real identity fields from sessions.db
    //
    let manifest_json = json!({
        "version": 1,
        "pack_type": "inspector_pack",

        // Real identity surfaced at top level
        "company_id": session.company_id,
        "session_key": session.session_key,
        "display_name": session.display_name,
        "session_id": session.id,

        // Core crypto + batch metadata
        "merkle_root": sess.merkle_root,
        "signature": { "key_id": sig.kid, "algorithm": "Ed25519" },
        "timestamp": ts_iso,

        // Legacy fields preserved if needed
        "file_count": files.len(),
    });

    //
    // ★ NEW: Full DB-backed session snapshot
    //
    let session_json = json!({
        "version": 1,
        "id": session.id,
        "session_key": session.session_key,
        "company_id": session.company_id,
        "display_name": session.display_name,
        "status": session.status,
        "created_at_ms": session.created_at_ms,
        "updated_at_ms": session.updated_at_ms,
        "session_root": session.session_root,
        "tl_seq": session.tl_seq,
        "company_root": session.company_root,
        "bundle_path": session.bundle_path,
        "bundle_sha256": session.bundle_sha256,
    });

    //
    // ★ Preserve transparency block inside session.json for attestation
    //
    let session_json = {
        let mut base = session_json;
        base["transparency"] = tl_block_json;
        base
    };


    // Best-effort JWKS snapshot: used both for attestation fingerprint and for
    // inclusion in the Inspector Pack as jwks.json. In stub mode this is fully
    // deterministic; in real-Core mode it reflects the current signing keys.
    let jwks_json = match core_client::fetch_jwks(&ctx) {
        Ok(j) => {
            let jwks_path = out_dir.join("jwks_snapshot.json");
            if let Err(e) = fs::write(&jwks_path, serde_json::to_string_pretty(&j)?) {
                eprintln!("warn: failed to write {}: {e}", jwks_path.display());
            } else {
                eprintln!("   │ jwks_snapshot: {}", jwks_path.display());
            }
            Some(j)
        }
        Err(e) => {
            eprintln!("warn: jwks fetch failed; attestation will omit fingerprint: {e}");
            None
        }
    };

    eprintln!("bundle: writing locally (preserve TL fields)");
    let bundle_path = core_client::bundle_save_zip_local(
        &out_dir,
        &resolved_label,
        &manifest_json,
        &session_json,
        jwks_json.as_ref(),
    )?;

    let ts_ms = Utc::now().timestamp_millis();
    let sha_list: Vec<String> = fresh.into_iter().map(|(_, s)| s).collect();
    let outputs = vec![
        bundle_path.to_string_lossy().to_string(),
        tl_proof_path.to_string_lossy().to_string(),
    ];
    state::mark_processed(&mut st, &sha_list, ts_ms, &outputs);
    let _ = state::save(&state_path, &st);

    if let Err(e) = generate_attestation(&out_dir, &bundle_path) {
        eprintln!("warn: attestation generation failed: {e}");
    }

    Ok(bundle_path)
}

fn generate_attestation(out_dir: &Path, bundle_path: &Path) -> Result<()> {
    let script = std::env::var("OORD_ATTEST_SCRIPT").unwrap_or_else(|_| "attestation/gen.py".to_string());
    let python = std::env::var("PYTHON_BIN").unwrap_or_else(|_| "python3".to_string());
    let out_pdf = out_dir.join("attestation.pdf");

    let status = Command::new(&python)
        .arg(&script)
        .arg("--bundle")
        .arg(bundle_path)
        .arg("--out")
        .arg(&out_pdf)
        .arg("--artifacts-dir")
        .arg(out_dir)
        .status()
        .with_context(|| format!("failed to spawn attestation generator using {} {}", python, script))?;

    if !status.success() {
        return Err(anyhow!("attestation generator exited with status {status}"));
    }

    let mut f = fs::File::open(&out_pdf)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let sha = format!("{:x}", hasher.finalize());
    println!("attestation_path={} sha256={}", out_pdf.display(), sha);

    Ok(())
}

fn sha256_file(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn resolve_batch_label(raw: &str, study_id: &str) -> String {
    let s = raw.trim();
    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let base = if s.is_empty() || s.contains("$(") {
        "batch-{ts}".to_string()
    } else {
        s.to_string()
    };
    base.replace("{ts}", &ts).replace("{study_id}", study_id)
}
