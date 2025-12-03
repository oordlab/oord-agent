#[test]
fn inspector_pack_contains_real_session_identity() {
    let tmp = tempdir().unwrap();
    let base = tmp.path();

    sessions_db::init_db(base).unwrap();

    let sess = sessions_db::create_session(
        base,
        "sess-T2-001",
        "ACME-LABS",
        Some("Real Session"),
    ).unwrap();

    // Build a fake pack using pipeline helper (you may wrap or extract pack logic)
    let pack_path = pipeline::build_inspector_pack_for_session(
        base,
        &sess,
        &[],
    ).unwrap();

    let mut zip = zip::ZipArchive::new(fs::File::open(&pack_path).unwrap()).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_reader(zip.by_name("manifest.json").unwrap()).unwrap();
    let session_json: serde_json::Value =
        serde_json::from_reader(zip.by_name("session.json").unwrap()).unwrap();

    assert_eq!(manifest["company_id"], "ACME-LABS");
    assert_eq!(manifest["session_key"], "sess-T2-001");
    assert_eq!(manifest["display_name"], "Real Session");

    assert_eq!(session_json["company_id"], "ACME-LABS");
    assert_eq!(session_json["session_key"], "sess-T2-001");
}