// gateway/src/main.rs
use gateway::{config, pipeline};
use gateway::csv_writer;
use gateway::sessions_db;
use gateway::core_client;

use anyhow::{Context, Result};
use clap::Parser;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{self, json};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;
use chrono::Utc;
use rusqlite::{Connection, params};

#[derive(Parser, Debug)]
#[command(name = "oord-lab-gateway")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, default_value_t = false)]
    once: bool,
    #[arg(long, default_value_t = false, help = "Watch input_dir and auto-run on changes")]
    watch: bool,
    #[arg(long, default_value_t = 800u64, help = "Debounce window in ms for watch mode")]
    debounce_ms: u64,
    #[arg(long, default_value_t = 8787u16, help = "Health port (HTTP GET /health)")]
    health_port: u16,
    #[arg(long, default_value_t = false, help = "Disable health endpoint")]
    no_health: bool,
}
fn update_session_finalize(
    base_dir: &Path,
    session_key: &str,
    session_root: &str,
    tl_seq: i64,
    company_root: Option<&str>,
) -> Result<sessions_db::SessionRecord> {
    let db_path = base_dir.join("_data").join("sessions.db");
    let conn = Connection::open(&db_path)
        .with_context(|| format!("failed to open sessions.db at {}", db_path.display()))?;
    let now_ms = Utc::now().timestamp_millis();

    conn.execute(
        r#"
        UPDATE sessions
        SET session_root  = ?1,
            tl_seq        = ?2,
            company_root  = ?3,
            status        = 'finalized',
            updated_at_ms = ?4
        WHERE session_key = ?5
        "#,
        params![session_root, tl_seq, company_root, now_ms, session_key],
    )
    .context("failed to update session finalize info")?;

    let updated = sessions_db::get_session_by_key(base_dir, session_key)?
        .ok_or_else(|| anyhow::anyhow!("session not found after finalize update"))?;
    Ok(updated)
}

struct FinalizeOutput {
    session: sessions_db::SessionRecord,
    tl: core_client::TLProof,
    jwks: Option<serde_json::Value>,
}

fn finalize_session(
    cfg: &config::Cfg,
    base_dir: &Path,
    session_key: &str,
) -> Result<FinalizeOutput> {
    // Ensure DB exists and fetch session + files
    sessions_db::init_db(base_dir)?;
    let sess = sessions_db::get_session_by_key(base_dir, session_key)?
        .ok_or_else(|| anyhow::anyhow!("session not found"))?;

    let files = sessions_db::list_files_for_session(base_dir, sess.id)?;
    if files.is_empty() {
        return Err(anyhow::anyhow!("no files attached to session"));
    }

    // Core context
    let ctx = core_client::CoreCtx {
        base_url: cfg.core.base_url.clone(),
        api_key: cfg.core.api_key.clone(),
    };

    // Ingest files -> unit CIDs
    let mut unit_cids = Vec::with_capacity(files.len());
    for f in &files {
        let p = Path::new(&f.storage_path);
        let resp = core_client::ingest_file(&ctx, p)?;
        unit_cids.push(resp.unit_cid);
    }

    // Core session + sign + TL submit
    let sess_resp = core_client::create_session(&ctx, &unit_cids)?;
    let _sig = core_client::sign_session(&ctx, &sess_resp.session_id)?;
    let proof = core_client::submit_tl(&ctx, &sess_resp.merkle_root)?;

    // Per-session out_dir under gateway/_out
    let out_dir = Path::new(&cfg.watcher.out_dir).join(&sess.session_key);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create session out_dir {}", out_dir.display()))?;

    // TL proof JSON
    let tl_json = json!({
        "tl_seq":       proof.tl_seq,
        "merkle_root":  proof.merkle_root,
        "sth_sig":      proof.sth_sig,
        "t_log_ms":     proof.t_log_ms,
        "company_root": proof.company_root,
    });
    let tl_path = out_dir.join("tl_proof.json");
    fs::write(&tl_path, serde_json::to_string_pretty(&tl_json)?)
        .with_context(|| format!("failed to write {}", tl_path.display()))?;

    // Best-effort JWKS snapshot
    let jwks = match core_client::fetch_jwks(&ctx) {
        Ok(j) => {
            let jwks_path = out_dir.join("jwks_snapshot.json");
            if let Err(e) =
                fs::write(&jwks_path, serde_json::to_string_pretty(&j)?)
            {
                eprintln!(
                    "warn: finalize: failed to write {}: {e}",
                    jwks_path.display()
                );
            } else {
                eprintln!(
                    "finalize: jwks_snapshot: {}",
                    jwks_path.display()
                );
            }
            Some(j)
        }
        Err(e) => {
            eprintln!("warn: finalize: jwks fetch failed: {e}");
            None
        }
    };

    // Update DB with finalize info
    let updated = update_session_finalize(
        base_dir,
        session_key,
        &sess_resp.merkle_root,
        proof.tl_seq as i64,
        proof.company_root.as_deref(),
    )?;

    Ok(FinalizeOutput {
        session: updated,
        tl: proof,
        jwks,
    })
}

fn spawn_control(cfg: Arc<config::Cfg>, port: u16) {
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let addr = format!("127.0.0.1:{port}");
        let listener = TcpListener::bind(&addr).unwrap();
        eprintln!("control: listening on {}", addr);

        // Helper to send plain-text error
        fn respond_text(s: &mut std::net::TcpStream, status: &str, body: &str) {
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
        }

        // Helper to send JSON
        fn respond_json(s: &mut std::net::TcpStream, status: &str, body_json: &str) {
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            let _ = s.write_all(resp.as_bytes());
        }

        'accept: for stream in listener.incoming() {
            let mut s = match stream {
                Ok(x) => x,
                Err(_) => continue,
            };

            // ----- Read raw bytes until end of headers (\r\n\r\n) -----
            let mut head = Vec::with_capacity(4096);
            let mut buf = [0u8; 1024];
            let header_end_idx = loop {
                match s.read(&mut buf) {
                    Ok(0) => break None,
                    Ok(n) => {
                        head.extend_from_slice(&buf[..n]);
                        if let Some(idx) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(idx + 4); // index after the \r\n\r\n
                        }
                    }
                    Err(_) => break None,
                }
            };

            let Some(header_end) = header_end_idx else {
                respond_text(&mut s, "400 Bad Request", "invalid HTTP headers");
                continue 'accept;
            };

            // Split header vs any body bytes already read
            let (header_bytes, body_initial) = head.split_at(header_end);
            let head_str = String::from_utf8_lossy(header_bytes);
            let mut lines = head_str.split("\r\n");

            let mut parts = lines.next().unwrap_or("").split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");

            let mut content_length: usize = 0;
            let mut x_filename: Option<String> = None;
            for line in lines {
                if line.is_empty() {
                    break;
                }
                if let Some(v) = line.strip_prefix("Content-Length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("X-Filename:") {
                    x_filename = Some(v.trim().to_string());
                }
            }

            // Small helper used in POST routes to assemble the body from the
            // bytes we already read plus any remaining bytes on the socket.
            fn read_body_from_stream(
                s: &mut TcpStream,
                content_length: usize,
                body_initial: &[u8],
            ) -> std::io::Result<Vec<u8>> {
                let mut body = vec![0u8; content_length];
                let mut offset = 0usize;

                if !body_initial.is_empty() && content_length > 0 {
                    let n0 = body_initial.len().min(content_length);
                    body[..n0].copy_from_slice(&body_initial[..n0]);
                    offset = n0;
                }

                while offset < content_length {
                    let n = s.read(&mut body[offset..])?;
                    if n == 0 {
                        break;
                    }
                    offset += n;
                }

                if offset < content_length {
                    // Truncate if we got less than declared; better than hanging.
                    body.truncate(offset);
                }

                Ok(body)
            }

            match (method, path) {
                // Health probe
                ("GET", "/health") => {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
                    let _ = s.write_all(resp.as_bytes());
                    continue 'accept;
                }

                // --- Task 7: Session Lifecycle API ---

                // Create a new session: POST /sessions
                ("POST", "/sessions") => {
                    let body = match read_body_from_stream(&mut s, content_length, body_initial) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to read body: {e}");
                            respond_text(&mut s, "400 Bad Request", &msg);
                            continue 'accept;
                        }
                    };

                    let v: serde_json::Value = match serde_json::from_slice(&body) {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = format!("invalid JSON: {e}");
                            respond_text(&mut s, "400 Bad Request", &msg);
                            continue 'accept;
                        }
                    };

                    let company_id = match v.get("company_id").and_then(|x| x.as_str()) {
                        Some(c) if !c.is_empty() => c,
                        _ => {
                            respond_text(&mut s, "400 Bad Request", "company_id is required");
                            continue 'accept;
                        }
                    };

                    // Simple safety for company IDs
                    if !company_id
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                    {
                        respond_text(&mut s, "400 Bad Request", "invalid company_id");
                        continue 'accept;
                    }

                    let display_name = v.get("display_name").and_then(|x| x.as_str());

                    // Session key is the external ID
                    let session_key = v
                        .get("session_key")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            let ts = chrono::Utc::now().timestamp_millis();
                            format!("sess-{ts}")
                        });

                    let base_dir = Path::new("gateway");
                    if let Err(e) = sessions_db::init_db(base_dir) {
                        let msg = format!("failed to init sessions.db: {e}");
                        respond_text(&mut s, "500 Internal Server Error", &msg);
                        continue 'accept;
                    }

                    let rec = match sessions_db::create_session(
                        base_dir,
                        &session_key,
                        company_id,
                        display_name,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("failed to create session: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };

                    let body_json = match serde_json::to_string(&rec) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to serialize session: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };
                    respond_json(&mut s, "201 Created", &body_json);
                    continue 'accept;
                }

                // Get a single session by session_key and include files
                ("GET", p) if p.starts_with("/sessions/") => {
                    let key = &p["/sessions/".len()..];
                    if key.is_empty() {
                        respond_text(&mut s, "400 Bad Request", "missing session key");
                        continue 'accept;
                    }

                    let base_dir = Path::new("gateway");

                    let sess_opt = match sessions_db::get_session_by_key(base_dir, key) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("failed to fetch session: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };

                    let Some(sess) = sess_opt else {
                        respond_text(&mut s, "404 Not Found", "session not found");
                        continue 'accept;
                    };

                    let files = match sessions_db::list_files_for_session(base_dir, sess.id) {
                        Ok(xs) => xs,
                        Err(e) => {
                            let msg = format!("failed to list session files: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };

                    let body_json = match serde_json::to_string(&json!({
                        "id": sess.id,
                        "session_key": sess.session_key,
                        "company_id": sess.company_id,
                        "display_name": sess.display_name,
                        "status": sess.status,
                        "created_at_ms": sess.created_at_ms,
                        "updated_at_ms": sess.updated_at_ms,
                        "session_root": sess.session_root,
                        "tl_seq": sess.tl_seq,
                        "company_root": sess.company_root,
                        "bundle_path": sess.bundle_path,
                        "bundle_sha256": sess.bundle_sha256,
                        "files": files,
                    })) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to serialize session detail: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };

                    respond_json(&mut s, "200 OK", &body_json);
                    continue 'accept;
                }

                // List sessions for a company: GET /companies/{id}/sessions
                ("GET", p) if p.starts_with("/companies/") && p.ends_with("/sessions") => {
                    let tail = &p["/companies/".len()..]; // e.g. "DEMO-LABS/sessions"
                    let company_id = match tail.strip_suffix("/sessions") {
                        Some(c) if !c.is_empty() => c,
                        _ => {
                            respond_text(&mut s, "400 Bad Request", "missing company id");
                            continue 'accept;
                        }
                    };

                    let base_dir = Path::new("gateway");
                    if let Err(e) = sessions_db::init_db(base_dir) {
                        let msg = format!("failed to init sessions.db: {e}");
                        respond_text(&mut s, "500 Internal Server Error", &msg);
                        continue 'accept;
                    }

                    let recs =
                        match sessions_db::list_sessions_for_company(base_dir, company_id, 100, 0) {
                            Ok(xs) => xs,
                            Err(e) => {
                                eprintln!("error: list_sessions_for_company failed: {e}");
                                let body = r#"{"ok":false,"error":"list_sessions_for_company failed"}"#;
                                respond_json(&mut s, "500 Internal Server Error", body);
                                continue 'accept;
                            }
                        };

                    let body_json = match serde_json::to_string(&json!({
                        "company_id": company_id,
                        "sessions": recs,
                    })) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to serialize sessions: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };
                    respond_json(&mut s, "200 OK", &body_json);
                    continue 'accept;
                }
                
                // Finalize a session: POST /sessions/{session_key}/finalize
                ("POST", p) if p.starts_with("/sessions/") && p.ends_with("/finalize") => {
                    let tail = &p["/sessions/".len()..]; // "sess-.../finalize"
                    let key = match tail.strip_suffix("/finalize") {
                        Some(x) if !x.is_empty() => x,
                        _ => {
                            respond_text(&mut s, "400 Bad Request", "invalid session finalize path");
                            continue 'accept;
                        }
                    };

                    let base_dir = Path::new("gateway");
                    let result = finalize_session(&cfg, base_dir, key);

                    match result {
                        Ok(out) => {
                            let body_json = match serde_json::to_string(&json!({
                                "session": out.session,
                                "tl": {
                                    "tl_seq": out.tl.tl_seq,
                                    "merkle_root": out.tl.merkle_root,
                                    "sth_sig": out.tl.sth_sig,
                                    "t_log_ms": out.tl.t_log_ms,
                                    "company_root": out.tl.company_root,
                                },
                                "jwks": out.jwks,
                            })) {
                                Ok(b) => b,
                                Err(e) => {
                                    let msg = format!("failed to serialize finalize response: {e}");
                                    respond_text(&mut s, "500 Internal Server Error", &msg);
                                    continue 'accept;
                                }
                            };
                            respond_json(&mut s, "200 OK", &body_json);
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("session not found") {
                                respond_text(&mut s, "404 Not Found", "session not found");
                            } else if msg.contains("no files attached") {
                                respond_text(&mut s, "400 Bad Request", "no files attached to session");
                            } else {
                                let body = format!("finalize failed: {msg}");
                                respond_text(&mut s, "500 Internal Server Error", &body);
                            }
                        }
                    }

                    continue 'accept;
                }
                
                // Attach a file to a session: POST /sessions/{session_key}/files
                ("POST", p) if p.starts_with("/sessions/") && p.ends_with("/files") => {
                    let tail = &p["/sessions/".len()..]; // "sess-.../files"
                    let key = match tail.strip_suffix("/files") {
                        Some(x) if !x.is_empty() => x,
                        _ => {
                            respond_text(&mut s, "400 Bad Request", "invalid session path");
                            continue 'accept;
                        }
                    };

                    let base_dir = Path::new("gateway");
                    if let Err(e) = sessions_db::init_db(base_dir) {
                        let msg = format!("failed to init sessions.db: {e}");
                        respond_text(&mut s, "500 Internal Server Error", &msg);
                        continue 'accept;
                    }

                    let sess_opt = match sessions_db::get_session_by_key(base_dir, key) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = format!("failed to fetch session: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };
                    let Some(sess) = sess_opt else {
                        respond_text(&mut s, "404 Not Found", "session not found");
                        continue 'accept;
                    };

                    let filename = x_filename
                        .clone()
                        .unwrap_or_else(|| "upload.bin".to_string());

                    // ⬇️ Use the shared body reader so we don't fight with body_initial
                    let body = match read_body_from_stream(&mut s, content_length, body_initial) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to read body: {e}");
                            respond_text(&mut s, "400 Bad Request", &msg);
                            continue 'accept;
                        }
                    };

                    let mut hasher = Sha256::new();
                    hasher.update(&body);
                    let sha = format!("{:x}", hasher.finalize());
                    let size_bytes = body.len() as u64;

                    let data_root = Path::new("gateway").join("_data");
                    let sess_dir = data_root.join("uploads").join(sess.id.to_string());
                    if let Err(e) = fs::create_dir_all(&sess_dir) {
                        let msg = format!("failed to create upload dir: {e}");
                        respond_text(&mut s, "500 Internal Server Error", &msg);
                        continue 'accept;
                    }
                    let dest_name = format!("{}-{}", &sha[..12], filename);
                    let dest_path = sess_dir.join(dest_name);
                    if !dest_path.exists() {
                        if let Err(e) = fs::write(&dest_path, &body) {
                            let msg = format!("failed to write upload: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    }

                    let file_rec = match sessions_db::insert_or_get_file(
                        base_dir,
                        sess.id,
                        &filename,
                        &dest_path,
                        size_bytes,
                        &sha,
                        None,
                        "source",
                    ) {
                        Ok(fr) => fr,
                        Err(e) => {
                            let msg = format!("failed to record file in DB: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };

                    let body_json = match serde_json::to_string(&json!({
                        "session": sess,
                        "file": file_rec,
                    })) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!("failed to serialize response: {e}");
                            respond_text(&mut s, "500 Internal Server Error", &msg);
                            continue 'accept;
                        }
                    };
                    respond_json(&mut s, "200 OK", &body_json);
                    continue 'accept;
                }
                

                // Existing dragdrop API (kept as-is, but with correct body reading)
                ("POST", "/api/dragdrop") => {
                    let body = match read_body_from_stream(&mut s, content_length, body_initial) {
                        Ok(b) => b,
                        Err(e) => {
                            let msg = format!(r#"{{"ok":false,"error":"failed to read body: {e}"}}"#);
                            respond_json(&mut s, "400 Bad Request", &msg);
                            continue 'accept;
                        }
                    };

                    let fname = x_filename.clone().unwrap_or_else(|| "upload.bin".to_string());
                    let save_path = Path::new(&cfg.watcher.input_dir).join(&fname);
                    if let Err(e) = fs::write(&save_path, &body) {
                        let msg = format!(r#"{{"ok":false,"error":"{}"}}"#, e);
                        respond_json(&mut s, "500 Internal Server Error", &msg);
                        continue 'accept;
                    }
                    match run_batch(&cfg) {
                        Ok(bundle) => {
                            let tl = Path::new(&cfg.watcher.out_dir).join("tl_proof.json");
                            let body = format!(
                                r#"{{"ok":true,"bundle_path":"{}","tl_proof":"{}"}}"#,
                                bundle.display(),
                                tl.display()
                            );
                            respond_json(&mut s, "200 OK", &body);
                        }
                        Err(e) => {
                            let msg = format!(r#"{{"ok":false,"error":"{}"}}"#, e);
                            respond_json(&mut s, "500 Internal Server Error", &msg);
                        }
                    }
                    continue 'accept;
                }

                // Fallback 404
                _ => {
                    respond_text(&mut s, "404 Not Found", "not found\n");
                    continue 'accept;
                }
            }
        }
    });
}

fn ensure_dirs(out_dir: &str) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let p = PathBuf::from(out_dir);
    if let Some(parent) = p.parent() {
        let data_root = parent.join("_data");
        fs::create_dir_all(&data_root).ok();
    }
    Ok(())
}

fn canonicalize_csv(csv_path: &str) {
    let src = Path::new(csv_path);
    if !src.exists() {
        eprintln!("warn: canonical CSV source missing: {}", csv_path);
        return;
    }
    let python = std::env::var("PYTHON_BIN").unwrap_or_else(|_| "python3".to_string());
    let script = "utils/canonicalizer/csv_canonicalizer.py";
    let out_path = "_out/vault_loader_canonical.csv";
    match Command::new(&python)
        .arg(script)
        .arg("--input")
        .arg(csv_path)
        .arg("--out")
        .arg(out_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                eprintln!(
                    "warn: csv canonicalizer failed: status={}",
                    output.status
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stdout.trim().is_empty() {
                    eprintln!("stdout: {}", stdout.trim());
                }
                if !stderr.trim().is_empty() {
                    eprintln!("stderr: {}", stderr.trim());
                }
            } else {
                let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("vault_loader_canonical_path={} sha256={}", out_path, digest);
            }
        }
        Err(e) => {
            eprintln!("warn: failed to spawn csv canonicalizer: {e}");
        }
    }
}

fn canonicalize_xlsx() {
    let src_path = Path::new("_out/IQOQ.xlsx");
    if !src_path.exists() {
        eprintln!("info: IQOQ.xlsx not found; skipping XLSX canonicalization");
        return;
    }
    let python = std::env::var("PYTHON_BIN").unwrap_or_else(|_| "python3".to_string());
    let script = "utils/canonicalizer/xlsx_canonicalizer.py";
    let out_path = "_out/IQOQ_canonical.xlsx";
    match Command::new(&python)
        .arg(script)
        .arg("--input")
        .arg(src_path)
        .arg("--out")
        .arg(out_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                eprintln!(
                    "warn: xlsx canonicalizer failed: status={}",
                    output.status
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stdout.trim().is_empty() {
                    eprintln!("stdout: {}", stdout.trim());
                }
                if !stderr.trim().is_empty() {
                    eprintln!("stderr: {}", stderr.trim());
                }
            } else {
                let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("IQOQ_canonical_path={} sha256={}", out_path, digest);
            }
        }
        Err(e) => {
            eprintln!("warn: failed to spawn xlsx canonicalizer: {e}");
        }
    }
}

/// Single “do a batch run” wrapper used by:
/// - CLI `--once`
/// - `/api/dragdrop`
/// - watch mode
fn run_batch(cfg: &config::Cfg) -> Result<PathBuf> {
    let files = pipeline::list_input_files(Path::new(&cfg.watcher.input_dir));
    let file_count = files.len();
    println!("found {} candidate files", file_count);

    let bundle = pipeline::on_new_files(files, cfg)?;
    println!("bundle_path={}", bundle.display());

    let csv_path =
        std::env::var("OORD_LAB_CSV").unwrap_or_else(|_| "_out/vault_loader.csv".to_string());
    let bundle_str = bundle.to_string_lossy().to_string();
    let rec = csv_writer::CsvRecord {
        session_id: "-",
        study_id: &cfg.lab.study_id,
        source_system: &cfg.lab.source_system,
        file_count,
        bundle_path: &bundle_str,
        merkle_root: "-",
    };
    if let Err(e) = csv_writer::append(&csv_path, &rec) {
        eprintln!("warn: vault_loader.csv append failed: {e}");
    } else {
        println!("csv: appended {}", csv_path);
    }

    canonicalize_csv(&csv_path);
    canonicalize_xlsx();

    Ok(bundle)
}

fn main_inner() -> Result<()> {
    let args = Args::parse();
    let cfg = config::load_cfg(&args.config).with_context(|| "failed to load config")?;
    config::validate_cfg(&cfg)?;
    ensure_dirs(&cfg.watcher.out_dir)?;

    // Initialize sessions.db under gateway/_data.
    sessions_db::init_db(Path::new("gateway"))?;

    let cfg_arc = Arc::new(cfg);
    let c: &config::Cfg = &*cfg_arc;

    if !args.no_health {
        spawn_control(cfg_arc.clone(), args.health_port);
    }
    println!(
        "lab: study_id={} source_system={}",
        c.lab.study_id, c.lab.source_system
    );

    if args.once {
        let bundle = run_batch(c)?;
        println!(
            "config_ok out_dir={} input_dir={}",
            c.watcher.out_dir, c.watcher.input_dir
        );
        println!("bundle_path={}", bundle.display());
        println!(
            "study_id={} source_system={}",
            c.lab.study_id, c.lab.source_system
        );
        return Ok(());
    }

    if args.watch {
        let (tx, rx) = mpsc::channel();
        let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
        watcher.watch(Path::new(&c.watcher.input_dir), RecursiveMode::NonRecursive)?;
        println!(
            "watching {} (debounce {}ms)",
            &c.watcher.input_dir, args.debounce_ms
        );
        let mut last: Option<Instant> = None;
        let mut last_fp: Option<u64> = None;

        fn folder_fingerprint(dir: &str) -> u64 {
            let mut h = DefaultHasher::new();
            for e in WalkDir::new(dir).max_depth(1).into_iter().flatten() {
                let p = e.path();
                if p.is_file() {
                    if let Ok(md) = p.metadata() {
                        let path = p.to_string_lossy();
                        let size = md.len();
                        let mtime = md
                            .modified()
                            .unwrap_or(SystemTime::UNIX_EPOCH)
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        (path.as_ref(), size, mtime).hash(&mut h);
                    }
                }
            }
            h.finish()
        }

        loop {
            match rx.recv() {
                Ok(Ok(event)) => {
                    let interesting =
                        matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                    if !interesting {
                        continue;
                    }
                    let now = Instant::now();
                    if matches!(last, Some(t) if now.duration_since(t).as_millis() < args.debounce_ms as u128)
                    {
                        continue;
                    }
                    last = Some(now);
                    let fp = folder_fingerprint(&c.watcher.input_dir);
                    if last_fp == Some(fp) {
                        eprintln!("skip: no material change detected");
                        continue;
                    }
                    last_fp = Some(fp);
                    match run_batch(c) {
                        Ok(b) => eprintln!("ok: {}", b.display()),
                        Err(e) => eprintln!("error: {e}"),
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("watch error: {e}");
                }
                Err(e) => {
                    eprintln!("channel error: {e}");
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }

    // Server mode: keep the process alive so /health, /api/dragdrop, and /sessions APIs work.
    println!("ready");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() {
    if let Err(e) = main_inner() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
