use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, ToolInfo, TrustMetadata, TrustStatus, PACK_WITNESS_SCHEMA_VERSION,
};
use paintgun::compose::{
    error_codes as compose_error_codes, verify_compose_with_signing, ComposeManifest,
    ComposeSummary, ComposeWitnesses, COMPOSE_WITNESS_SCHEMA_VERSION,
};
use paintgun::signing::sign_manifest_file;
use paintgun::verify::{verify_ctc_with_allowlist_and_signing, VerifyProfile};

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

fn manifest_entry_for(path: &Path) -> ManifestEntry {
    let bytes = fs::read(path).expect("read artifact");
    ManifestEntry {
        file: path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("artifact file name")
            .to_string(),
        sha256: sha256_prefixed(&bytes),
        size: bytes.len() as u64,
    }
}

fn write_ctc_fixture(root: &PathBuf) -> PathBuf {
    fs::create_dir_all(root).expect("fixture dir");

    let resolver_bytes = br#"{"version":"2025.10","sets":{},"modifiers":{},"resolutionOrder":[]}"#;
    let resolved_bytes = br#"{"axes":{},"resolvedByContext":{"(base)":[]}}"#;
    let witnesses_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "witnessSchema": PACK_WITNESS_SCHEMA_VERSION,
        "conflictMode": "semantic",
        "policyDigest": "sha256:dummy",
        "gaps": [],
        "conflicts": [],
        "inherited": [],
        "bcViolations": [],
        "orthogonality": []
    }))
    .expect("serialize witnesses");

    fs::write(root.join("resolver.json"), resolver_bytes).expect("resolver");
    fs::write(root.join("resolved.json"), resolved_bytes).expect("resolved");
    fs::write(root.join("ctc.witnesses.json"), &witnesses_bytes).expect("witnesses");

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
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
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
        required_artifacts: Vec::new(),
        admissibility_witnesses_sha256: None,
    };

    let manifest_path = root.join("ctc.manifest.json");
    write_json(&manifest_path, &manifest);
    manifest_path
}

fn write_compose_fixture(root: &PathBuf) -> PathBuf {
    fs::create_dir_all(root).expect("fixture dir");

    let witnesses = ComposeWitnesses {
        witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some("sha256:dummy".to_string()),
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let witnesses_bytes = serde_json::to_vec_pretty(&witnesses).expect("compose witnesses");
    fs::write(root.join("compose.witnesses.json"), &witnesses_bytes).expect("witnesses");

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        axes: BTreeMap::new(),
        pack_order: Vec::new(),
        packs: Vec::new(),
        trust: TrustMetadata::unsigned(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 0,
            contexts: 1,
            token_paths_union: 0,
            overlapping_token_paths: 0,
            conflicts: 0,
        },
        witnesses_sha256: sha256_prefixed(&witnesses_bytes),
    };

    let manifest_path = root.join("compose.manifest.json");
    write_json(&manifest_path, &manifest);
    manifest_path
}

fn write_compose_fixture_with_pack(root: &PathBuf, pack_dir: &Path) -> PathBuf {
    let compose_dir = root.join("compose");
    fs::create_dir_all(&compose_dir).expect("compose dir");

    let witnesses = ComposeWitnesses {
        witness_schema: COMPOSE_WITNESS_SCHEMA_VERSION,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some("sha256:dummy".to_string()),
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let witnesses_bytes = serde_json::to_vec_pretty(&witnesses).expect("compose witnesses");
    fs::write(compose_dir.join("compose.witnesses.json"), &witnesses_bytes)
        .expect("write compose witnesses");

    let pack_manifest_path = pack_dir.join("ctc.manifest.json");
    let pack_manifest: CtcManifest =
        serde_json::from_slice(&fs::read(&pack_manifest_path).expect("read pack manifest"))
            .expect("parse pack manifest");
    let pack_dir_rel = format!(
        "../{}",
        pack_dir
            .file_name()
            .and_then(|name| name.to_str())
            .expect("pack dir name")
    );

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "tbp-rs".to_string(),
            version: "0.1.0".to_string(),
        },
        axes: BTreeMap::new(),
        pack_order: vec![pack_manifest.pack_identity.pack_id.clone()],
        packs: vec![tbp::compose::ComposePackEntry {
            name: pack_manifest.pack_identity.pack_id.clone(),
            dir: pack_dir_rel,
            pack_identity: pack_manifest.pack_identity.clone(),
            ctc_manifest: manifest_entry_for(&pack_manifest_path),
            ctc_witnesses: manifest_entry_for(&pack_dir.join("ctc.witnesses.json")),
            resolved_json: manifest_entry_for(&pack_dir.join("resolved.json")),
            authored_json: None,
        }],
        trust: TrustMetadata::unsigned(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 1,
            contexts: 1,
            token_paths_union: 0,
            overlapping_token_paths: 0,
            conflicts: 0,
        },
        witnesses_sha256: sha256_prefixed(&witnesses_bytes),
    };

    let manifest_path = compose_dir.join("compose.manifest.json");
    write_json(&manifest_path, &manifest);
    manifest_path
}

#[test]
fn verify_require_signed_rejects_unsigned_ctc_manifest() {
    let root = temp_dir("signing-unsigned-ctc");
    let manifest = write_ctc_fixture(&root);

    let report = verify_ctc_with_allowlist_and_signing(&manifest, None, false, None, true);
    assert!(
        !report.ok,
        "unsigned manifest should fail when signed is required"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("trust.status must be 'signed'")),
        "expected signed trust status failure, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn sign_ctc_manifest_allows_signed_verification() {
    let root = temp_dir("signing-ctc");
    let manifest = write_ctc_fixture(&root);

    let sig_path = sign_manifest_file(&manifest, None, Some("ci@test")).expect("sign ctc");
    assert!(sig_path.exists(), "signature file should be written");

    let signed: CtcManifest = serde_json::from_slice(&fs::read(&manifest).expect("read manifest"))
        .expect("parse manifest");
    assert_eq!(signed.trust.status, TrustStatus::Signed);

    let report = verify_ctc_with_allowlist_and_signing(&manifest, None, false, None, true);
    assert!(
        report.ok,
        "signed manifest should verify: {:?}",
        report.errors
    );
}

#[test]
fn tampered_signed_ctc_manifest_fails_signature_verification() {
    let root = temp_dir("signing-tamper-ctc");
    let manifest = write_ctc_fixture(&root);

    sign_manifest_file(&manifest, None, Some("ci@test")).expect("sign ctc");

    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("read manifest")).expect("parse json");
    value["spec"] = serde_json::json!("2025.11");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&value).expect("serialize tampered manifest"),
    )
    .expect("write tampered manifest");

    let report = verify_ctc_with_allowlist_and_signing(&manifest, None, false, None, true);
    assert!(
        !report.ok,
        "tampered signed manifest should fail verification"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("signature verification failed")),
        "expected signature verification failure, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn tampered_signed_ctc_manifest_gate_hash_fails_signature_verification() {
    let root = temp_dir("signing-tamper-ctc-gate-hash");
    let manifest = write_ctc_fixture(&root);

    sign_manifest_file(&manifest, None, Some("ci@test")).expect("sign ctc");

    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("read manifest")).expect("parse json");
    value["admissibilityWitnessesSha256"] = serde_json::json!("sha256:tampered");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&value).expect("serialize tampered manifest"),
    )
    .expect("write tampered manifest");

    let report = verify_ctc_with_allowlist_and_signing(&manifest, None, false, None, true);
    assert!(
        !report.ok,
        "tampered signed manifest should fail verification"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("signature verification failed")),
        "expected signature verification failure, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn sign_compose_manifest_allows_signed_verification() {
    let root = temp_dir("signing-compose");
    let manifest = write_compose_fixture(&root);

    let sig_path = sign_manifest_file(&manifest, None, Some("ci@test")).expect("sign compose");
    assert!(sig_path.exists(), "signature file should be written");

    let report = verify_compose_with_signing(
        &manifest,
        None,
        false,
        false,
        true,
        false,
        VerifyProfile::Core,
    );
    assert!(
        report.ok,
        "signed compose manifest should verify: {:?}",
        report.errors
    );
}

#[test]
fn verify_require_signed_rejects_unsigned_compose_manifest() {
    let root = temp_dir("signing-unsigned-compose");
    let pack_dir = root.join("pack");
    write_ctc_fixture(&pack_dir);
    let manifest = write_compose_fixture_with_pack(&root, &pack_dir);

    let report = verify_compose_with_signing(
        &manifest,
        None,
        false,
        false,
        true,
        false,
        VerifyProfile::Core,
    );
    assert!(
        !report.ok,
        "unsigned compose manifest should fail when signed is required"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("compose manifest trust.status must be 'signed'")),
        "expected compose signed trust status failure, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == compose_error_codes::SIGNATURE_REQUIRED),
        "expected compose signature-required code, got:\n{:?}",
        report.error_details
    );
}

#[test]
fn verify_require_packs_signed_rejects_unsigned_pack_manifest() {
    let root = temp_dir("signing-unsigned-pack");
    let pack_dir = root.join("pack");
    write_ctc_fixture(&pack_dir);
    let manifest = write_compose_fixture_with_pack(&root, &pack_dir);

    let report = verify_compose_with_signing(
        &manifest,
        None,
        false,
        false,
        false,
        true,
        VerifyProfile::Core,
    );
    assert!(
        !report.ok,
        "unsigned pack manifest should fail when signed packs are required"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("[fixture-pack:trust] pack manifest trust.status must be 'signed'")),
        "expected pack signature requirement failure, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == compose_error_codes::SIGNATURE_REQUIRED),
        "expected pack signature-required code, got:\n{:?}",
        report.error_details
    );
}

#[test]
fn verify_require_signed_and_packs_signed_accepts_signed_bundle() {
    let root = temp_dir("signing-fully-signed-compose");
    let pack_dir = root.join("pack");
    let pack_manifest = write_ctc_fixture(&pack_dir);
    sign_manifest_file(&pack_manifest, None, Some("ci@test")).expect("sign pack");

    let compose_manifest = write_compose_fixture_with_pack(&root, &pack_dir);
    sign_manifest_file(&compose_manifest, None, Some("ci@test")).expect("sign compose");

    let report = verify_compose_with_signing(
        &compose_manifest,
        None,
        false,
        false,
        true,
        true,
        VerifyProfile::Core,
    );
    assert!(
        report.ok,
        "fully signed compose bundle should verify: {:?}",
        report.errors
    );
}

#[test]
fn verify_rejects_mismatched_pack_witness_schema_version() {
    let root = temp_dir("signing-pack-witness-schema");
    let manifest_path = write_ctc_fixture(&root);

    let witnesses_path = root.join("ctc.witnesses.json");
    let mut witnesses_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&witnesses_path).expect("read witnesses"))
            .expect("parse witnesses json");
    witnesses_json["witnessSchema"] = serde_json::json!(PACK_WITNESS_SCHEMA_VERSION + 1);
    write_json(&witnesses_path, &witnesses_json);

    let witnesses_bytes = fs::read(&witnesses_path).expect("read rewritten witnesses");
    let mut manifest: CtcManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest.witnesses_sha256 = sha256_prefixed(&witnesses_bytes);
    write_json(&manifest_path, &manifest);

    let report = verify_ctc_with_allowlist_and_signing(&manifest_path, None, false, None, false);
    assert!(
        !report.ok,
        "mismatched pack witness schema should fail verify"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsupported pack witness schema version")),
        "expected schema-version failure, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_rejects_mismatched_compose_witness_schema_version() {
    let root = temp_dir("signing-compose-witness-schema");
    let manifest_path = write_compose_fixture(&root);

    let witnesses_path = root.join("compose.witnesses.json");
    let mut witnesses_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&witnesses_path).expect("read compose witnesses"))
            .expect("parse compose witnesses json");
    witnesses_json["witnessSchema"] = serde_json::json!(COMPOSE_WITNESS_SCHEMA_VERSION + 1);
    write_json(&witnesses_path, &witnesses_json);

    let witnesses_bytes = fs::read(&witnesses_path).expect("read rewritten compose witnesses");
    let mut manifest: ComposeManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read compose manifest"))
            .expect("parse compose manifest");
    manifest.witnesses_sha256 = sha256_prefixed(&witnesses_bytes);
    write_json(&manifest_path, &manifest);

    let report = verify_compose_with_signing(
        &manifest_path,
        None,
        false,
        false,
        false,
        false,
        VerifyProfile::Core,
    );
    assert!(
        !report.ok,
        "mismatched compose witness schema should fail verify-compose"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsupported compose witness schema version")),
        "expected compose schema-version failure, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == compose_error_codes::WITNESS_SCHEMA_INVALID),
        "expected compose witness schema code, got:\n{:?}",
        report.error_details
    );
}
