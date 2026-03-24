use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::allowlist::{
    Allowlist, BcAllowEntry, BcSelector, ConflictAllowEntry, ConflictSelector,
};
use paintgun::artifact::write_resolved_json;
use paintgun::cert::{
    analyze_composability, build_ctc_manifest, render_validation_report, ConflictMode,
};
use paintgun::ids::{TokenPathId, WitnessId};
use paintgun::policy::Policy;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};
use paintgun::verify::verify_ctc_with_allowlist;

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn build_charter_pack(out: &Path) -> (PathBuf, PathBuf, paintgun::cert::CtcAnalysis) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let resolved_path = out.join("resolved.json");
    write_resolved_json(&resolved_path, &store).expect("write resolved");

    let validation_txt = render_validation_report(&store, &analysis);
    let validation_path = out.join("validation.txt");
    fs::write(&validation_path, validation_txt).expect("write validation");

    let witnesses_path = out.join("ctc.witnesses.json");
    let witnesses_bytes =
        serde_json::to_vec_pretty(&analysis.witnesses).expect("serialize witnesses");
    fs::write(&witnesses_path, &witnesses_bytes).expect("write witnesses");
    let witnesses_sha256 = format!("sha256:{}", paintgun::util::sha256_hex(&witnesses_bytes));

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
        analysis.summary.clone(),
        witnesses_sha256,
    );
    let manifest_path = out.join("ctc.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    (manifest_path, witnesses_path, analysis)
}

#[test]
fn allowlist_by_witness_id_can_suppress_composability_failures() {
    let out = temp_dir("allowlist-id");
    let (manifest, witnesses, analysis) = build_charter_pack(&out);

    assert!(
        !analysis.witnesses.conflicts.is_empty(),
        "fixture assumption changed: expected Kan conflicts"
    );
    assert!(
        !analysis.witnesses.bc_violations.is_empty(),
        "fixture assumption changed: expected BC violations"
    );

    let allowlist = Allowlist {
        version: 1,
        conflicts: analysis
            .witnesses
            .conflicts
            .iter()
            .map(|w| ConflictAllowEntry {
                witness_id: Some(WitnessId::from(w.witness_id.as_str())),
                selector: None,
                reason: "accepted tie-break for rollout".to_string(),
            })
            .collect(),
        bc_violations: analysis
            .witnesses
            .bc_violations
            .iter()
            .map(|w| BcAllowEntry {
                witness_id: Some(WitnessId::from(w.witness_id.as_str())),
                selector: None,
                reason: "accepted BC tie-break for rollout".to_string(),
            })
            .collect(),
    };

    let report = verify_ctc_with_allowlist(&manifest, Some(&witnesses), true, Some(&allowlist));
    assert!(
        !report
            .errors
            .iter()
            .any(|e| e.contains("Kan conflicts") || e.contains("BC violations")),
        "allowlist should suppress conflict/BC composability failures, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report.errors.iter().any(|e| e.contains("Kan gaps")),
        "expected remaining gap failure, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        !report.notes.is_empty(),
        "verify should annotate allowlisted findings"
    );
}

#[test]
fn allowlist_by_selector_can_suppress_composability_failures() {
    let out = temp_dir("allowlist-selector");
    let (manifest, witnesses, analysis) = build_charter_pack(&out);

    let allowlist = Allowlist {
        version: 1,
        conflicts: analysis
            .witnesses
            .conflicts
            .iter()
            .map(|w| ConflictAllowEntry {
                witness_id: None,
                selector: Some(ConflictSelector {
                    token_path: TokenPathId::from(w.token_path.as_str()),
                    target: w.target.clone(),
                }),
                reason: "known cross-axis tie-break".to_string(),
            })
            .collect(),
        bc_violations: analysis
            .witnesses
            .bc_violations
            .iter()
            .map(|w| BcAllowEntry {
                witness_id: None,
                selector: Some(BcSelector {
                    token_path: TokenPathId::from(w.token_path.as_str()),
                    axis_a: w.axis_a.clone(),
                    value_a: w.value_a.clone(),
                    axis_b: w.axis_b.clone(),
                    value_b: w.value_b.clone(),
                }),
                reason: "known BC tie-break".to_string(),
            })
            .collect(),
    };

    let report = verify_ctc_with_allowlist(&manifest, Some(&witnesses), true, Some(&allowlist));
    assert!(
        !report
            .errors
            .iter()
            .any(|e| e.contains("Kan conflicts") || e.contains("BC violations")),
        "allowlist selectors should suppress conflict/BC composability failures, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report.errors.iter().any(|e| e.contains("Kan gaps")),
        "expected remaining gap failure, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn stale_allowlist_entries_fail_with_clear_reason() {
    let out = temp_dir("allowlist-stale");
    let (manifest, witnesses, _analysis) = build_charter_pack(&out);

    let allowlist = Allowlist {
        version: 1,
        conflicts: vec![ConflictAllowEntry {
            witness_id: Some(WitnessId::from("conflict-deadbeefdeadbeef")),
            selector: None,
            reason: "old issue no longer present".to_string(),
        }],
        bc_violations: vec![],
    };

    let report = verify_ctc_with_allowlist(&manifest, Some(&witnesses), false, Some(&allowlist));
    assert!(!report.ok, "stale allowlist should fail verify");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("stale allowlist entry")),
        "expected stale allowlist error, got:\n{}",
        report.errors.join("\n")
    );
}
