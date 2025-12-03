use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use chrono::{SecondsFormat, Utc};

#[derive(Debug, Clone)]
pub struct CsvRecord<'a> {
    pub session_id: &'a str,
    pub study_id: &'a str,
    pub source_system: &'a str,
    pub file_count: usize,
    pub bundle_path: &'a str,
    pub merkle_root: &'a str,
}

fn csv_escape(field: &str) -> String {
    let needs_quotes = field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r');
    if !needs_quotes {
        return field.to_string();
    }
    let escaped = field.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

fn header_line() -> &'static str {
    "timestamp_utc,session_id,study_id,source_system,file_count,out_bundle_path,merkle_root\n"
}

fn build_line(rec: &CsvRecord) -> String {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    [
        csv_escape(&ts),
        csv_escape(rec.session_id),
        csv_escape(rec.study_id),
        csv_escape(rec.source_system),
        rec.file_count.to_string(),
        csv_escape(rec.bundle_path),
        csv_escape(rec.merkle_root),
    ]
    .join(",") + "\n"
}

/// Append a CSV line to `path`, creating parent dirs and header if needed.
pub fn append(path: &str, rec: &CsvRecord) -> io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let file_exists = Path::new(path).exists();
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    if !file_exists {
        f.write_all(header_line().as_bytes())?;
    }
    f.write_all(build_line(rec).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn test_build_line_shape() {
        let r = CsvRecord {
            session_id: "sess123",
            study_id: "DEMO",
            source_system: "ns",
            file_count: 2,
            bundle_path: "_out/inspector_pack_batch-123.zip",
            merkle_root: "abc123",
        };
        let line = build_line(&r);
        assert!(line.contains("sess123"));
        assert!(line.contains("_out/inspector_pack_batch-123.zip"));
        assert!(line.ends_with('\n'));
    }
}
