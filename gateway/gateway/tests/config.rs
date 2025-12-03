// gateway/tests/config.rs
use std::env;
use std::path::PathBuf;

#[test]
fn parse_example_yaml() {
    env::set_var("OORD_CORE_API_KEY", "testkey");
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("configs/lab.config.yaml");
    let cfg = gateway::config::load_cfg(&p).unwrap();
    gateway::config::validate_cfg(&cfg).unwrap();
    assert_eq!(cfg.core.api_key, "devkey");
    assert!(cfg.watcher.out_dir.contains("_out"));
}
