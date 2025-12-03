use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Entry {
    pub status: String,          // "processed" | "error" | "pending"
    pub ts_ms: i64,              // logical timestamp you prefer
    pub outputs: Vec<String>,    // paths we emitted (bundle, logs, etc)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub files: BTreeMap<String, Entry>,  // sha256 -> entry
}

pub fn load(p: &Path) -> State {
    if let Ok(s) = fs::read_to_string(p) {
        if let Ok(t) = serde_json::from_str::<State>(&s) {
            return t;
        }
    }
    State::default()
}

pub fn save(p: &Path, st: &State) -> Result<()> {
    let s = serde_json::to_string_pretty(st)?;
    fs::write(p, s)?;
    Ok(())
}

pub fn is_seen(st: &State, sha: &str) -> bool {
    st.files.contains_key(sha)
}

pub fn mark_processed(st: &mut State, sha_list: &[String], ts_ms: i64, outputs: &[String]) {
    for sha in sha_list {
        st.files.insert(sha.clone(), Entry{
            status: "processed".to_string(),
            ts_ms,
            outputs: outputs.to_vec(),
        });
    }
}
