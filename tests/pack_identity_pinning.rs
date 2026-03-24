use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::artifact::write_resolved_json;
use paintgun::cert::{
    analyze_composability, build_ctc_manifest, render_validation_report, ConflictMode,
};
use paintgun::policy::Policy;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};
use paintgun::verify::verify_ctc;

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("dist-test-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

struct CleanupDir(PathBuf);

impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn verify_enforces_pinned_pack_identity_content_hash() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let out = temp_dir("pack-id-pin");
    let _cleanup = CleanupDir(out.clone());
    let resolved_path = out.join("resolved.json");
    write_resolved_json(&resolved_path, &store).expect("write resolved");

    let validation = render_validation_report(&store, &analysis);
    let validation_path = out.join("validation.txt");
    fs::write(&validation_path, validation).expect("write validation");

    let witnesses_path = out.join("ctc.witnesses.json");
    let witnesses_bytes =
        serde_json::to_vec_pretty(&analysis.witnesses).expect("serialize witnesses");
    fs::write(&witnesses_path, &witnesses_bytes).expect("write witnesses");
    let witnesses_sha = format!("sha256:{}", paintgun::util::sha256_hex(&witnesses_bytes));

    let manifest = build_ctc_manifest(
        &doc,
        &resolver_path,
        &store,
        Some(&Policy::default()),
        ConflictMode::Semantic,
        &resolved_path,
        None,
        None,
        None,
        None,
        None,
        Some(&validation_path),
        Vec::new(),
        analysis.summary.clone(),
        witnesses_sha,
    );
    assert_eq!(manifest.pack_identity.pack_id, "Charter Steel");
    assert_eq!(manifest.pack_identity.pack_version, doc.version);
    assert_eq!(
        manifest.pack_identity.content_hash,
        manifest.outputs.resolved_json.sha256
    );

    let manifest_path = out.join("ctc.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    let ok = verify_ctc(&manifest_path, Some(&witnesses_path), false);
    assert!(
        ok.ok,
        "expected valid manifest, got:\n{}",
        ok.errors.join("\n")
    );

    let mut tampered = manifest.clone();
    tampered.pack_identity.content_hash = "sha256:deadbeef".to_string();
    let tampered_path = out.join("ctc.tampered.manifest.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).expect("serialize tampered manifest"),
    )
    .expect("write tampered manifest");

    let bad = verify_ctc(&tampered_path, Some(&witnesses_path), false);
    assert!(
        !bad.ok,
        "expected verify failure for mismatched packIdentity.contentHash"
    );
    assert!(
        bad.errors
            .iter()
            .any(|e| e.contains("packIdentity.contentHash mismatch")),
        "expected pack identity mismatch diagnostic, got:\n{}",
        bad.errors.join("\n")
    );
}
