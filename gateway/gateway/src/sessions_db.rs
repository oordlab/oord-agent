// gateway/src/sessions_db.rs
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use rusqlite::OptionalExtension;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};


#[derive(Debug, Clone, Serialize)]
pub struct SessionRecord {
    pub id: i64,
    pub session_key: String,
    pub company_id: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub session_root: Option<String>,
    pub tl_seq: Option<i64>,
    pub company_root: Option<String>,
    pub bundle_path: Option<String>,
    pub bundle_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRecord {
    pub id: i64,
    pub session_id: i64,
    pub logical_name: String,
    pub storage_path: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub content_type: Option<String>,
    pub role: String,
    pub created_at_ms: i64,
}

fn db_path(base_dir: &Path) -> PathBuf {
    base_dir.join("_data").join("sessions.db")
}


fn open_conn(base_dir: &Path) -> Result<Connection> {
    let path = db_path(base_dir);
    let conn = Connection::open(path).context("failed to open sessions.db")?;
    Ok(conn)
}

pub fn init_db(base_dir: &Path) -> Result<()> {
    eprintln!(
        "sessions_db::init_db base_dir={} db_path={}",
        base_dir.display(),
        db_path(base_dir).display()
    );

    let data_dir = base_dir.join("_data");
    fs::create_dir_all(&data_dir).context("failed to create gateway/_data directory")?;
    let path = db_path(base_dir);
    let conn = Connection::open(path).context("failed to create sessions.db")?;

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS sessions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_key     TEXT NOT NULL UNIQUE,
            company_id      TEXT NOT NULL,
            display_name    TEXT,
            created_at_ms   INTEGER NOT NULL,
            updated_at_ms   INTEGER NOT NULL,
            status          TEXT NOT NULL,
            session_root    TEXT,
            tl_seq          INTEGER,
            company_root    TEXT,
            bundle_path     TEXT,
            bundle_sha256   TEXT
        );

        CREATE TABLE IF NOT EXISTS files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      INTEGER NOT NULL,
            logical_name    TEXT NOT NULL,
            storage_path    TEXT NOT NULL,
            size_bytes      INTEGER NOT NULL,
            sha256          TEXT NOT NULL,
            content_type    TEXT,
            role            TEXT NOT NULL DEFAULT 'source',
            created_at_ms   INTEGER NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_company_id
            ON sessions (company_id);

        CREATE INDEX IF NOT EXISTS idx_sessions_status
            ON sessions (status);

        CREATE INDEX IF NOT EXISTS idx_files_session_id
            ON files (session_id);

        CREATE INDEX IF NOT EXISTS idx_files_sha256
            ON files (sha256);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_files_session_sha256
            ON files (session_id, sha256);
        "#,
    )
    .context("failed to initialize sessions.db schema")?;

    Ok(())
}

fn map_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        id: row.get(0)?,
        session_key: row.get(1)?,
        company_id: row.get(2)?,
        display_name: row.get(3)?,
        created_at_ms: row.get(4)?,
        updated_at_ms: row.get(5)?,
        status: row.get(6)?,
        session_root: row.get(7)?,
        tl_seq: row.get(8)?,
        company_root: row.get(9)?,
        bundle_path: row.get(10)?,
        bundle_sha256: row.get(11)?,
    })
}

fn map_file_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRecord> {
    Ok(FileRecord {
        id: row.get(0)?,
        session_id: row.get(1)?,
        logical_name: row.get(2)?,
        storage_path: row.get(3)?,
        size_bytes: row.get(4)?,
        sha256: row.get(5)?,
        content_type: row.get(6)?,
        role: row.get(7)?,
        created_at_ms: row.get(8)?,
    })
}

/// Create a new session or return the existing one if `session_key` already exists.
pub fn create_session(
    base_dir: &Path,
    session_key: &str,
    company_id: &str,
    display_name: Option<&str>,
) -> Result<SessionRecord> {
    let now_ms = Utc::now().timestamp_millis();
    let conn = open_conn(base_dir)?;

    conn.execute(
        r#"
        INSERT OR IGNORE INTO sessions (
            session_key,
            company_id,
            display_name,
            created_at_ms,
            updated_at_ms,
            status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, 'pending')
        "#,
        params![
            session_key,
            company_id,
            display_name,
            now_ms,
            now_ms,
        ],
    )
    .context("failed to insert session")?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_key,
                company_id,
                display_name,
                created_at_ms,
                updated_at_ms,
                status,
                session_root,
                tl_seq,
                company_root,
                bundle_path,
                bundle_sha256
            FROM sessions
            WHERE session_key = ?1
            "#,
        )
        .context("failed to prepare session lookup")?;

    let rec = stmt
        .query_row(params![session_key], map_session_row)
        .context("failed to fetch session after insert")?;

    Ok(rec)
}

/// Look up a session by its external key.
pub fn get_session_by_key(base_dir: &Path, session_key: &str) -> Result<Option<SessionRecord>> {
    let conn = open_conn(base_dir)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_key,
                company_id,
                display_name,
                created_at_ms,
                updated_at_ms,
                status,
                session_root,
                tl_seq,
                company_root,
                bundle_path,
                bundle_sha256
            FROM sessions
            WHERE session_key = ?1
            "#,
        )
        .context("failed to prepare session lookup")?;

    let rec = stmt
        .query_row(params![session_key], map_session_row)
        .optional()
        .context("failed to fetch session")?;

    Ok(rec)
}
/// Look up a session by its numeric id.
pub fn get_session_by_id(base_dir: &Path, id: i64) -> Result<Option<SessionRecord>> {
    let conn = open_conn(base_dir)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_key,
                company_id,
                display_name,
                created_at_ms,
                updated_at_ms,
                status,
                session_root,
                tl_seq,
                company_root,
                bundle_path,
                bundle_sha256
            FROM sessions
            WHERE id = ?1
            "#,
        )
        .context("failed to prepare session lookup by id")?;

    let rec = stmt
        .query_row(params![id], map_session_row)
        .optional()
        .context("failed to fetch session by id")?;

    Ok(rec)
}
/// Insert a file row for a session, deduping on (session_id, sha256).
pub fn insert_or_get_file(
    base_dir: &Path,
    session_id: i64,
    logical_name: &str,
    storage_path: &Path,
    size_bytes: u64,
    sha256: &str,
    content_type: Option<&str>,
    role: &str,
) -> Result<FileRecord> {
    let conn = open_conn(base_dir)?;
    let now_ms = Utc::now().timestamp_millis();
    let storage_str = storage_path.to_string_lossy().to_string();

    conn.execute(
        r#"
        INSERT OR IGNORE INTO files (
            session_id,
            logical_name,
            storage_path,
            size_bytes,
            sha256,
            content_type,
            role,
            created_at_ms
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            session_id,
            logical_name,
            storage_str,
            size_bytes as i64,
            sha256,
            content_type,
            role,
            now_ms,
        ],
    )
    .context("failed to insert file")?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_id,
                logical_name,
                storage_path,
                size_bytes,
                sha256,
                content_type,
                role,
                created_at_ms
            FROM files
            WHERE session_id = ?1 AND sha256 = ?2
            "#,
        )
        .context("failed to prepare file lookup")?;

    let rec = stmt
        .query_row(params![session_id, sha256], map_file_row)
        .context("failed to fetch file after insert")?;

    Ok(rec)
}

/// List all files for a session.
pub fn list_files_for_session(base_dir: &Path, session_id: i64) -> Result<Vec<FileRecord>> {
    let conn = open_conn(base_dir)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_id,
                logical_name,
                storage_path,
                size_bytes,
                sha256,
                content_type,
                role,
                created_at_ms
            FROM files
            WHERE session_id = ?1
            ORDER BY id ASC
            "#,
        )
        .context("failed to prepare list_files_for_session")?;

    let rows = stmt
        .query_map(params![session_id], map_file_row)
        .context("failed to iterate files")?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// List sessions for a given company, ordered by created_at_ms DESC.
pub fn list_sessions_for_company(
    base_dir: &Path,
    company_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<SessionRecord>> {
    let conn = open_conn(base_dir)?;
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                id,
                session_key,
                company_id,
                display_name,
                created_at_ms,
                updated_at_ms,
                status,
                session_root,
                tl_seq,
                company_root,
                bundle_path,
                bundle_sha256
            FROM sessions
            WHERE company_id = ?1
            ORDER BY created_at_ms DESC, id DESC
            LIMIT ?2 OFFSET ?3
            "#,
        )
        .context("failed to prepare list_sessions_for_company")?;

    let rows = stmt
        .query_map(params![company_id, limit, offset], map_session_row)
        .context("failed to iterate sessions")?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_init_db_creates_schema() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();

        let db = db_path(base);
        assert!(db.exists(), "sessions.db should exist");

        let conn = Connection::open(db).unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        let mut names = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let name: String = row.get(0).unwrap();
            names.push(name);
        }

        assert!(names.contains(&"sessions".to_string()));
        assert!(names.contains(&"files".to_string()));
    }

    #[test]
    fn test_create_session_and_fetch() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();

        let created = create_session(base, "sess-demo-001", "ACME-LABS", Some("Demo Session"))
            .expect("create_session failed");

        assert_eq!(created.session_key, "sess-demo-001");
        assert_eq!(created.company_id, "ACME-LABS");
        assert_eq!(created.status, "pending");

        let fetched = get_session_by_key(base, "sess-demo-001")
            .expect("get_session_by_key failed")
            .expect("session not found");

        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.display_name, Some("Demo Session".to_string()));
    }

    #[test]
    fn test_insert_or_get_file_dedupes_sha256() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();

        let sess = create_session(base, "sess-demo-002", "ACME-LABS", None).unwrap();

        let storage = base.join("uploads").join("file1.pdf");
        let f1 = insert_or_get_file(
            base,
            sess.id,
            "file1.pdf",
            &storage,
            1234,
            "deadbeef",
            Some("application/pdf"),
            "source",
        )
        .unwrap();

        let f2 = insert_or_get_file(
            base,
            sess.id,
            "file1.pdf",
            &storage,
            1234,
            "deadbeef",
            Some("application/pdf"),
            "source",
        )
        .unwrap();

        assert_eq!(f1.id, f2.id, "same (session_id, sha256) should dedupe");

        let listed = list_files_for_session(base, sess.id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sha256, "deadbeef");
    }

    #[test]
    fn test_get_session_by_id_roundtrip() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();
        let created = create_session(base, "sess-demo-004", "ACME-LABS", Some("ByID")).unwrap();

        let by_id = get_session_by_id(base, created.id)
            .expect("get_session_by_id failed")
            .expect("session not found by id");

        assert_eq!(by_id.session_key, "sess-demo-004");
        assert_eq!(by_id.company_id, "ACME-LABS");
        assert_eq!(by_id.display_name, Some("ByID".to_string()));
    }

    #[test]
    fn test_list_files_for_session() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();

        let sess = create_session(base, "sess-demo-003", "ACME-LABS", None).unwrap();

        let storage1 = base.join("uploads").join("a.pdf");
        let storage2 = base.join("uploads").join("b.pdf");

        insert_or_get_file(
            base,
            sess.id,
            "a.pdf",
            &storage1,
            100,
            "aaaa",
            Some("application/pdf"),
            "source",
        )
        .unwrap();

        insert_or_get_file(
            base,
            sess.id,
            "b.pdf",
            &storage2,
            200,
            "bbbb",
            Some("application/pdf"),
            "source",
        )
        .unwrap();

        let listed = list_files_for_session(base, sess.id).unwrap();
        assert_eq!(listed.len(), 2);
        let shas: Vec<String> = listed.into_iter().map(|f| f.sha256).collect();
        assert!(shas.contains(&"aaaa".to_string()));
        assert!(shas.contains(&"bbbb".to_string()));
    }

    #[test]
    fn test_list_sessions_for_company() {
        let tmp = tempdir().unwrap();
        let base = tmp.path();

        init_db(base).unwrap();

        let s1 = create_session(base, "sess-a", "ACME-LABS", None).unwrap();
        let s2 = create_session(base, "sess-b", "ACME-LABS", None).unwrap();
        let _s3 = create_session(base, "sess-c", "OTHER-LABS", None).unwrap();

        let xs = list_sessions_for_company(base, "ACME-LABS", 10, 0).unwrap();
        let keys: Vec<String> = xs.into_iter().map(|s| s.session_key).collect();
        assert!(keys.contains(&s1.session_key));
        assert!(keys.contains(&s2.session_key));
        assert!(!keys.contains(&"sess-c".to_string()));
    }
}
