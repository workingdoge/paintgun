use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, RequiredArtifactBinding, RequiredArtifactKind, ToolInfo, TrustMetadata,
    PACK_WITNESS_SCHEMA_VERSION,
};
use paintgun::compose::{
    verify_compose_with_signing, ComposeManifest, ComposePackEntry, ComposeSummary,
    ComposeWitnesses, COMPOSE_WITNESS_SCHEMA_VERSION,
};
use paintgun::gate::{GateFailure, GateResult, GateWitnesses, GATE_WITNESS_SCHEMA_VERSION};
use paintgun::kcir_v2::error_codes as kcir_error_codes;
use paintgun::verify::{
    error_codes as verify_error_codes, verify_ctc_with_options, CtcVerifyOptions, VerifyProfile,
};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", paintgun::util::sha256_hex(bytes))
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize");
    fs::write(path, bytes).expect("write json");
}

fn entry_for(path: &PathBuf, file: &str) -> ManifestEntry {
    let bytes = fs::read(path).expect("read fixture file");
    ManifestEntry {
        file: file.to_string(),
        sha256: sha256_prefixed(&bytes),
        size: bytes.len() as u64,
    }
}

fn accepted_admissibility() -> GateWitnesses {
    GateWitnesses {
        witness_schema: GATE_WITNESS_SCHEMA_VERSION,
        profile: "full".to_string(),
        result: GateResult::Accepted,
        failures: Vec::new(),
    }
}

fn rejected_admissibility() -> GateWitnesses {
    GateWitnesses {
        witness_schema: GATE_WITNESS_SCHEMA_VERSION,
        profile: "full".to_string(),
        result: GateResult::Rejected,
        failures: vec![GateFailure {
            witness_id: "gate-1".to_string(),
            class_name: "stability_failure".to_string(),
            law_ref: "GATE-3.1".to_string(),
            message: "reindex composition does not commute".to_string(),
            context: Some("theme:dark".to_string()),
            token_path: Some("color.surface.bg".to_string()),
            sources: Vec::new(),
            details: None,
        }],
    }
}

fn write_pack_fixture(
    root: &PathBuf,
    admissibility: Option<GateWitnesses>,
    include_admissibility_binding: bool,
) -> PathBuf {
    fs::create_dir_all(root).expect("fixture dir");

    let resolver_bytes = br#"{"version":"2025.10","sets":{},"modifiers":{},"resolutionOrder":[]}"#;
    let resolved_bytes = br#"{"axes":{},"resolvedByContext":{"(base)":[]}}"#;
    let witnesses_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "witnessSchema": PACK_WITNESS_SCHEMA_VERSION,
        "conflictMode": "semantic",
        "gaps": [],
        "conflicts": [],
        "inherited": [],
        "bcViolations": [],
        "orthogonality": []
    }))
    .expect("serialize ctc witnesses");

    fs::write(root.join("resolver.json"), resolver_bytes).expect("resolver");
    fs::write(root.join("resolved.json"), resolved_bytes).expect("resolved");
    fs::write(root.join("ctc.witnesses.json"), &witnesses_bytes).expect("ctc witnesses");

    let mut admissibility_witnesses_sha256: Option<String> = None;
    let mut required_artifacts = vec![RequiredArtifactBinding {
        kind: RequiredArtifactKind::CtcWitnesses,
        entry: entry_for(&root.join("ctc.witnesses.json"), "ctc.witnesses.json"),
    }];
    if let Some(admissibility_witnesses) = admissibility {
        let admissibility_bytes =
            serde_json::to_vec_pretty(&admissibility_witnesses).expect("serialize admissibility");
        fs::write(
            root.join("admissibility.witnesses.json"),
            &admissibility_bytes,
        )
        .expect("admissibility witnesses");
        required_artifacts.push(RequiredArtifactBinding {
            kind: RequiredArtifactKind::AdmissibilityWitnesses,
            entry: entry_for(
                &root.join("admissibility.witnesses.json"),
                "admissibility.witnesses.json",
            ),
        });
        if include_admissibility_binding {
            admissibility_witnesses_sha256 = Some(sha256_prefixed(&admissibility_bytes));
        }
    }
    required_artifacts.sort_by_key(|binding| binding.kind.as_str());

    let manifest = CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: "fixture-pack".to_string(),
            pack_version: "2025.10".to_string(),
            content_hash: sha256_prefixed(resolved_bytes),
        },
        trust: TrustMetadata::unsigned(),
        profile: Some(paintgun::kcir_v2::default_kcir_profile_binding()),
        axes: BTreeMap::new(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: None,
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        backend_artifacts: Vec::new(),
        native_api_versions: None,
        inputs: CtcInputs {
            resolver_spec: ManifestEntry {
                file: "resolver.json".to_string(),
                sha256: sha256_prefixed(resolver_bytes),
                size: resolver_bytes.len() as u64,
            },
            token_docs: Vec::new(),
        },
        outputs: CtcOutputs {
            resolved_json: ManifestEntry {
                file: "resolved.json".to_string(),
                sha256: sha256_prefixed(resolved_bytes),
                size: resolved_bytes.len() as u64,
            },
            tokens_css: None,
            tokens_swift: None,
            tokens_kotlin: None,
            tokens_dts: None,
            authored_json: None,
            validation_txt: None,
        },
        summary: CtcSummary {
            tokens: 0,
            contexts: 1,
            kan_gaps: 0,
            kan_conflicts: 0,
            kan_inherited: 0,
            bc_violations: 0,
            orthogonality_overlaps: 0,
        },
        witnesses_sha256: sha256_prefixed(&witnesses_bytes),
        required_artifacts,
        admissibility_witnesses_sha256,
    };

    let manifest_path = root.join("ctc.manifest.json");
    write_json(&manifest_path, &manifest);
    manifest_path
}

#[test]
fn verify_full_profile_accepts_bound_accepted_admissibility() {
    let root = temp_dir("verify-full-ok");
    let manifest_path = write_pack_fixture(&root, Some(accepted_admissibility()), true);

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            profile: VerifyProfile::Full,
            ..CtcVerifyOptions::default()
        },
    );
    assert!(report.ok, "expected full-profile verification success");
}

#[test]
fn verify_full_profile_rejects_missing_admissibility_hash_binding() {
    let root = temp_dir("verify-full-missing-binding");
    let manifest_path = write_pack_fixture(&root, Some(accepted_admissibility()), false);

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            profile: VerifyProfile::Full,
            ..CtcVerifyOptions::default()
        },
    );
    assert!(!report.ok, "expected full-profile verification failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("admissibilityWitnessesSha256 binding")),
        "expected missing binding error, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_full_profile_rejects_missing_required_admissibility_artifact_binding() {
    let root = temp_dir("verify-full-missing-required-artifact");
    let manifest_path = write_pack_fixture(&root, Some(accepted_admissibility()), true);
    let mut manifest_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let required = manifest_json
        .get_mut("requiredArtifacts")
        .and_then(|v| v.as_array_mut())
        .expect("requiredArtifacts array");
    required.retain(|entry| {
        entry
            .get("kind")
            .and_then(|k| k.as_str())
            .map(|k| k != "admissibilityWitnesses")
            .unwrap_or(true)
    });
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_json).expect("serialize manifest"),
    )
    .expect("write manifest");

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            profile: VerifyProfile::Full,
            ..CtcVerifyOptions::default()
        },
    );
    assert!(!report.ok, "expected full-profile verification failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("requiredArtifacts entry 'admissibilityWitnesses'")),
        "expected missing requiredArtifacts error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == verify_error_codes::FULL_PROFILE_BINDING_MISSING),
        "expected FULL_PROFILE_BINDING_MISSING code, got:\n{:?}",
        report.error_details
    );
}

#[test]
fn verify_full_profile_rejects_admissibility_hash_mismatch() {
    let root = temp_dir("verify-full-hash-mismatch");
    let manifest_path = write_pack_fixture(&root, Some(accepted_admissibility()), true);
    fs::write(
        root.join("admissibility.witnesses.json"),
        b"{\"tampered\":true}\n",
    )
    .expect("tamper admissibility");

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            profile: VerifyProfile::Full,
            ..CtcVerifyOptions::default()
        },
    );
    assert!(!report.ok, "expected full-profile verification failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("admissibility witnesses hash mismatch")),
        "expected admissibility hash mismatch error, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_full_profile_rejects_rejected_admissibility_result() {
    let root = temp_dir("verify-full-gate-rejected");
    let manifest_path = write_pack_fixture(&root, Some(rejected_admissibility()), true);

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            profile: VerifyProfile::Full,
            ..CtcVerifyOptions::default()
        },
    );
    assert!(!report.ok, "expected full-profile verification failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("full-profile admissibility verification failed")),
        "expected admissibility rejection error, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_compose_pack_profile_full_enforces_pack_admissibility_binding() {
    let root = temp_dir("verify-compose-pack-full");
    let pack_dir = root.join("pack");
    let _pack_manifest_path = write_pack_fixture(&pack_dir, Some(accepted_admissibility()), false);

    let compose_dir = root.join("compose");
    fs::create_dir_all(&compose_dir).expect("compose dir");
    let compose_witnesses = ComposeWitnesses {
        witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: None,
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let compose_witnesses_bytes =
        serde_json::to_vec_pretty(&compose_witnesses).expect("compose witnesses");
    fs::write(
        compose_dir.join("compose.witnesses.json"),
        &compose_witnesses_bytes,
    )
    .expect("write compose witnesses");

    let pack_manifest_bytes =
        fs::read(pack_dir.join("ctc.manifest.json")).expect("read pack manifest");
    let pack_manifest: CtcManifest =
        serde_json::from_slice(&pack_manifest_bytes).expect("parse pack manifest");
    let compose_manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        axes: BTreeMap::new(),
        pack_order: vec!["fixture-pack".to_string()],
        packs: vec![ComposePackEntry {
            name: "fixture-pack".to_string(),
            dir: "../pack".to_string(),
            pack_identity: pack_manifest.pack_identity.clone(),
            ctc_manifest: entry_for(&pack_dir.join("ctc.manifest.json"), "ctc.manifest.json"),
            ctc_witnesses: entry_for(&pack_dir.join("ctc.witnesses.json"), "ctc.witnesses.json"),
            resolved_json: entry_for(&pack_dir.join("resolved.json"), "resolved.json"),
            authored_json: None,
        }],
        trust: TrustMetadata::unsigned(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: None,
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        backend_artifacts: Vec::new(),
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 1,
            contexts: 1,
            token_paths_union: 0,
            overlapping_token_paths: 0,
            conflicts: 0,
        },
        witnesses_sha256: sha256_prefixed(&compose_witnesses_bytes),
    };
    let compose_manifest_path = compose_dir.join("compose.manifest.json");
    write_json(&compose_manifest_path, &compose_manifest);

    let report = verify_compose_with_signing(
        &compose_manifest_path,
        None,
        true,
        false,
        false,
        false,
        VerifyProfile::Full,
    );
    assert!(
        !report.ok,
        "compose verify should fail when pack full-profile binding is missing"
    );
    assert!(
        report.errors.iter().any(|e| e.contains(
            "[fixture-pack] full-profile verify requires manifest admissibilityWitnessesSha256 binding"
        )),
        "expected pack full-profile enforcement error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == verify_error_codes::FULL_PROFILE_BINDING_MISSING),
        "expected FULL_PROFILE_BINDING_MISSING code, got:\n{:?}",
        report.error_details
    );
}

#[test]
fn verify_compose_checks_pack_profile_binding_without_deep_pack_verify() {
    let root = temp_dir("verify-compose-pack-profile-binding");
    let pack_dir = root.join("pack");
    let _pack_manifest_path = write_pack_fixture(&pack_dir, Some(accepted_admissibility()), true);

    let mut pack_manifest_json: serde_json::Value =
        serde_json::from_slice(&fs::read(pack_dir.join("ctc.manifest.json")).expect("read pack"))
            .expect("parse pack");
    pack_manifest_json["profile"] = serde_json::Value::Null;
    fs::write(
        pack_dir.join("ctc.manifest.json"),
        serde_json::to_vec_pretty(&pack_manifest_json).expect("serialize modified pack"),
    )
    .expect("write modified pack");

    let compose_dir = root.join("compose");
    fs::create_dir_all(&compose_dir).expect("compose dir");
    let compose_witnesses = ComposeWitnesses {
        witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: None,
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let compose_witnesses_bytes =
        serde_json::to_vec_pretty(&compose_witnesses).expect("serialize compose witnesses");
    fs::write(
        compose_dir.join("compose.witnesses.json"),
        &compose_witnesses_bytes,
    )
    .expect("write compose witnesses");

    let pack_manifest_bytes =
        fs::read(pack_dir.join("ctc.manifest.json")).expect("read modified pack manifest");
    let pack_manifest: CtcManifest =
        serde_json::from_slice(&pack_manifest_bytes).expect("parse modified pack manifest");

    let compose_manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        axes: BTreeMap::new(),
        pack_order: vec!["fixture-pack".to_string()],
        packs: vec![ComposePackEntry {
            name: "fixture-pack".to_string(),
            dir: "../pack".to_string(),
            pack_identity: pack_manifest.pack_identity.clone(),
            ctc_manifest: entry_for(&pack_dir.join("ctc.manifest.json"), "ctc.manifest.json"),
            ctc_witnesses: entry_for(&pack_dir.join("ctc.witnesses.json"), "ctc.witnesses.json"),
            resolved_json: entry_for(&pack_dir.join("resolved.json"), "resolved.json"),
            authored_json: None,
        }],
        trust: TrustMetadata::unsigned(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: None,
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        backend_artifacts: Vec::new(),
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 1,
            contexts: 1,
            token_paths_union: 0,
            overlapping_token_paths: 0,
            conflicts: 0,
        },
        witnesses_sha256: sha256_prefixed(&compose_witnesses_bytes),
    };
    let compose_manifest_path = compose_dir.join("compose.manifest.json");
    write_json(&compose_manifest_path, &compose_manifest);

    let report = verify_compose_with_signing(
        &compose_manifest_path,
        None,
        false,
        false,
        false,
        false,
        VerifyProfile::Core,
    );
    assert!(
        !report.ok,
        "compose verify should fail on invalid referenced pack profile binding"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("[fixture-pack] manifest profile missing")),
        "expected profile-binding message, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == kcir_error_codes::PROFILE_MISMATCH),
        "expected PROFILE_MISMATCH code, got:\n{:?}",
        report.error_details
    );
}
