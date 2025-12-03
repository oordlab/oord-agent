// gateway/tests/pipeline.rs
use std::{env, fs, path::PathBuf};

#[test]
fn batch_pipeline_stub_core() {
    // Stub Core so the pipeline is deterministic and fast.
    env::set_var("OORD_CORE_API_KEY", "testkey");
    env::set_var("OORD_CORE_STUB", "1");

    // Move CWD to the repo root (tests start in the crate dir).
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // .../oord-lab/gateway
    let repo_root = crate_dir.parent().expect("no parent for crate dir").to_path_buf(); // .../oord-lab
    env::set_current_dir(&repo_root).expect("failed to chdir to repo root");

    // Load config from repo-root path (this file exists).
    let cfg_path = PathBuf::from("configs/lab.config.yaml");
    let cfg = gateway::config::load_cfg(&cfg_path).expect("failed to load config");
    gateway::config::validate_cfg(&cfg).expect("config validation failed");

    // Resolve input/output dirs exactly as the config sees them.
    let in_dir = PathBuf::from(&cfg.watcher.input_dir);
    let out_dir = PathBuf::from(&cfg.watcher.out_dir);

    // 🔧 Important: wipe prior state so the dedupe layer doesn't think everything is cached.
    if in_dir.exists() {
        fs::remove_dir_all(&in_dir).expect("failed to wipe input dir");
    }
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("failed to wipe out dir");
    }

    // Recreate a clean input/output layout.
    fs::create_dir_all(&in_dir).expect("failed to create input dir");
    fs::create_dir_all(&out_dir).expect("failed to create out dir");

    // Also remove any leftover state.json explicitly, in case something recreated out_dir.
    let state_path = out_dir.join("state.json");
    if state_path.exists() {
        fs::remove_file(&state_path).expect("failed to remove state.json");
    }

    // Seed two fresh PDFs for this test run.
    fs::write(in_dir.join("a.pdf"), b"stub").expect("failed to write a.pdf");
    fs::write(in_dir.join("b.pdf"), b"stub2").expect("failed to write b.pdf");

    // Run pipeline (shared lib entrypoint).
    let files = vec![in_dir.join("a.pdf"), in_dir.join("b.pdf")];
    let bundle_path = gateway::pipeline::on_new_files(files, &cfg)
        .expect("pipeline on_new_files failed");

    assert!(
        bundle_path.exists(),
        "bundle zip should exist in {}",
        bundle_path.display()
    );
    assert_eq!(
        bundle_path
            .extension()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase(),
        "zip",
        "bundle should be a .zip"
    );
}
