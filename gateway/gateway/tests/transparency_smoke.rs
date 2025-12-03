use std::fs;
use std::path::PathBuf;
use zip::ZipArchive;
use std::fs::File;

#[test]
#[ignore] // Run this after generating a bundle: `cargo test -p gateway --test transparency_smoke -- --ignored`
fn session_contains_transparency_block() {
    // Look for _out/ next to the crate root (repo-level) and inside the crate.
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate_dirs = [
        crate_root.parent().map(|p| p.join("_out")), // ../_out (repo root)
        Some(crate_root.join("_out")),               // ./gateway/_out (crate local)
    ];
    let mut out_dir: Option<PathBuf> = None;
    for d in candidate_dirs.into_iter().flatten() {
        if d.is_dir() { out_dir = Some(d); break; }
    }
    let out_dir = out_dir.expect("Could not locate _out directory (checked ../_out and ./gateway/_out). Run the gateway once first.");

    let mut latest: Option<PathBuf> = None;
    if let Ok(entries) = fs::read_dir(&out_dir) {
        let mut zips: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.starts_with("inspector_pack_") && s.ends_with(".zip"))
                        .unwrap_or(false)
            })
            .collect();
        zips.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
        latest = zips.pop();
    }
    let zip_path = latest.unwrap_or_else(|| {
        eprintln!("No inspector_pack_*.zip found in {}", out_dir.display());
        if let Ok(entries) = fs::read_dir(&out_dir) {
            for e in entries.flatten() {
                eprintln!("found: {}", e.path().display());
            }
        }
        panic!("No inspector_pack_*.zip found. Run the gateway once first.");
    });
    


    // Open ZIP and read session.json
    let file = File::open(&zip_path).expect("failed to open zip");
    let mut za = ZipArchive::new(file).expect("invalid zip");
    let mut session = String::new();
    {
        let mut f = za.by_name("session.json").expect("session.json not in ZIP");
        use std::io::Read;
        f.read_to_string(&mut session).expect("read session.json failed");
    }

    // Parse and assert transparency block
    let v: serde_json::Value = serde_json::from_str(&session).expect("invalid session.json");
    let t = v.get("transparency").expect("session.json missing 'transparency'");
    assert!(t.get("tl_seq").is_some(), "missing tl_seq");
    let root = t.get("merkle_root").and_then(|x| x.as_str()).expect("missing merkle_root");
    assert!(root.starts_with("cid:sha256:"), "merkle_root must start with cid:sha256:");
}
