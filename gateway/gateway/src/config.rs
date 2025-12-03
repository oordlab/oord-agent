use anyhow::{anyhow, Result};
use regex::Regex;
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Debug, Deserialize, Clone)]
pub struct CoreCfg { pub base_url: String, pub api_key: String }
#[derive(Debug, Deserialize, Clone)]
pub struct LabCfg { pub study_id: String, pub source_system: String }
#[derive(Debug, Deserialize, Clone)]
pub struct WatcherCfg { pub input_dir: String, pub out_dir: String, pub batch_label: String }
#[derive(Debug, Deserialize, Clone)]
pub struct BundleCfg { pub include_bytes: bool, pub include_verifier: bool, pub locale: String }
#[derive(Debug, Deserialize, Clone)]
pub struct AttestationCfg { pub template: String }

#[derive(Debug, Deserialize, Clone)]
pub struct Cfg {
    pub core: CoreCfg,
    pub lab: LabCfg,
    pub watcher: WatcherCfg,
    pub bundle: BundleCfg,
    pub attestation: AttestationCfg,
}

fn expand_env(s: &str) -> String {
    let re = Regex::new(r"\$\{([A-Z0-9_]+)\}").unwrap();
    re.replace_all(s, |caps: &regex::Captures| env::var(&caps[1]).unwrap_or_default()).to_string()
}

pub fn load_cfg(p: &Path) -> Result<Cfg> {
    let raw = fs::read_to_string(p)?;
    let expanded = expand_env(&raw);
    let cfg: Cfg = serde_yaml::from_str(&expanded)?;
    Ok(cfg)
}

pub fn validate_cfg(cfg: &Cfg) -> Result<()> {
    if cfg.core.base_url.trim().is_empty() { return Err(anyhow!("core.base_url required")); }
    if cfg.core.api_key.trim().is_empty() { return Err(anyhow!("core.api_key required")); }
    if cfg.watcher.input_dir.trim().is_empty() { return Err(anyhow!("watcher.input_dir required")); }
    if cfg.watcher.out_dir.trim().is_empty() { return Err(anyhow!("watcher.out_dir required")); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn env_expansion_works() {
        std::env::set_var("X_KEY", "abc123");
        let s = "api_key: \"${X_KEY}\"";
        let y = format!("core:\n  base_url: http://x\n  {}\nlab:\n  study_id: a\n  source_system: b\nwatcher:\n  input_dir: ./in\n  out_dir: ./out\n  batch_label: test\nbundle:\n  include_bytes: false\n  include_verifier: true\n  locale: en\nattestation:\n  template: ./t.md\n", s);
        let cfg: Cfg = serde_yaml::from_str(&expand_env(&y)).unwrap();
        assert_eq!(cfg.core.api_key, "abc123");
    }

    #[test]
    fn validate_cfg_catches_missing_fields() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("c.yml");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "core:\n  base_url: \"\"\n  api_key: \"\"\nlab:\n  study_id: a\n  source_system: b\nwatcher:\n  input_dir: \"\"\n  out_dir: \"\"\n  batch_label: x\nbundle:\n  include_bytes: false\n  include_verifier: true\n  locale: en\nattestation:\n  template: ./t.md").unwrap();
        let cfg = load_cfg(&p).unwrap();
        let err = validate_cfg(&cfg).unwrap_err().to_string();
        assert!(err.contains("core.base_url") || err.contains("core.api_key") || err.contains("watcher.input_dir") || err.contains("watcher.out_dir"));
    }
}

