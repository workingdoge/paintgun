use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tbp::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, ToolInfo, TrustMetadata, PACK_WITNESS_SCHEMA_VERSION,
};
use tbp::kcir_v2::{
    KcirProfileAnchor, KcirProfileBinding, MerkleProfile, ProfileAnchors,
    WIRE_FORMAT_LENPREFIXED_REF_V1,
};
use tbp::verify::{verify_ctc_with_options, CtcVerifyOptions};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tbp-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", tbp::util::sha256_hex(bytes))
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) {
    let bytes = serde_json::to_vec_pretty(value).expect("serialize");
    fs::write(path, bytes).expect("write json");
}

fn write_pack_with_profile_anchor(
    root: &PathBuf,
    root_commitment_hex: &str,
    epoch: u64,
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
    .expect("serialize witnesses");

    fs::write(root.join("resolver.json"), resolver_bytes).expect("resolver");
    fs::write(root.join("resolved.json"), resolved_bytes).expect("resolved");
    fs::write(root.join("ctc.witnesses.json"), &witnesses_bytes).expect("ctc witnesses");

    let manifest = CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "tbp-rs".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: "fixture-pack".to_string(),
            pack_version: "2025.10".to_string(),
            content_hash: sha256_prefixed(resolved_bytes),
        },
        trust: TrustMetadata::unsigned(),
        profile: Some(KcirProfileBinding {
            scheme_id: "hash".to_string(),
            params_hash: format!(
                "sha256:{}",
                hex::encode(tbp::kcir_v2::HashProfile::default_params_hash())
            ),
            wire_format_id: "kcir.wire.legacy-fixed32.v1".to_string(),
            wire_format_version: Some("1".to_string()),
            evidence_format_version: Some("1".to_string()),
            anchor: Some(KcirProfileAnchor {
                root_commitment: Some(root_commitment_hex.to_string()),
                tree_epoch: Some(epoch),
            }),
        }),
        axes: BTreeMap::new(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: None,
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

fn mutate_manifest_json(manifest_path: &PathBuf, mutate: impl FnOnce(&mut serde_json::Value)) {
    let bytes = fs::read(manifest_path).expect("read manifest");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse manifest");
    mutate(&mut v);
    let out = serde_json::to_vec_pretty(&v).expect("serialize manifest");
    fs::write(manifest_path, out).expect("write manifest");
}

#[test]
fn verify_ctc_accepts_matching_expected_profile_anchor() {
    let root = temp_dir("verify-kcir-anchor-ok");
    let expected_root = vec![0xAB; 32];
    let manifest_path = write_pack_with_profile_anchor(
        &root,
        &format!("sha256:{}", hex::encode(&expected_root)),
        9,
    );

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            expected_profile_anchors: Some(ProfileAnchors {
                root_commitment: Some(expected_root),
                tree_epoch: Some(9),
                metadata: BTreeMap::new(),
            }),
            ..CtcVerifyOptions::default()
        },
    );
    assert!(
        report.ok,
        "expected anchor match success: {:?}",
        report.errors
    );
}

#[test]
fn verify_ctc_rejects_mismatched_expected_profile_anchor() {
    let root = temp_dir("verify-kcir-anchor-mismatch");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);

    let report = verify_ctc_with_options(
        &manifest_path,
        CtcVerifyOptions {
            expected_profile_anchors: Some(ProfileAnchors {
                root_commitment: Some(vec![0xCD; 32]),
                tree_epoch: Some(7),
                metadata: BTreeMap::new(),
            }),
            ..CtcVerifyOptions::default()
        },
    );
    assert!(!report.ok, "expected anchor mismatch failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("rootCommitment mismatch")),
        "expected root commitment mismatch, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::kcir_v2::error_codes::ANCHOR_MISMATCH),
        "expected structured anchor mismatch code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_ctc_rejects_kcir_version_mismatch() {
    let root = temp_dir("verify-kcir-version-mismatch");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["kcirVersion"] = serde_json::Value::String("1".to_string());
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(!report.ok, "expected kcirVersion mismatch failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("kcirVersion mismatch")),
        "expected kcirVersion mismatch error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::verify::error_codes::KCIR_VERSION_MISMATCH),
        "expected structured kcir version mismatch code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_ctc_rejects_missing_manifest_profile_binding() {
    let root = temp_dir("verify-kcir-profile-missing");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"] = serde_json::Value::Null;
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(!report.ok, "expected missing profile failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("manifest profile missing")),
        "expected missing profile error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::kcir_v2::error_codes::PROFILE_MISMATCH),
        "expected structured profile mismatch code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_ctc_rejects_profile_params_hash_mismatch() {
    let root = temp_dir("verify-kcir-params-mismatch");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"]["paramsHash"] = serde_json::Value::String("sha256:deadbeef".to_string());
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(!report.ok, "expected paramsHash mismatch failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("profile.paramsHash mismatch")),
        "expected paramsHash mismatch error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::kcir_v2::error_codes::PARAMS_HASH_MISMATCH),
        "expected structured params hash mismatch code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_ctc_rejects_missing_profile_evidence_format_version() {
    let root = temp_dir("verify-kcir-evidence-format-missing");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"]["evidenceFormatVersion"] = serde_json::Value::Null;
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(!report.ok, "expected missing evidenceFormatVersion failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("manifest profile.evidenceFormatVersion missing")),
        "expected evidenceFormatVersion missing error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::kcir_v2::error_codes::EVIDENCE_MALFORMED),
        "expected structured evidence malformed code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_ctc_accepts_supported_merkle_profile_binding() {
    let root = temp_dir("verify-kcir-merkle-profile");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"]["schemeId"] = serde_json::Value::String("merkle".to_string());
        v["profile"]["paramsHash"] = serde_json::Value::String(format!(
            "sha256:{}",
            hex::encode(MerkleProfile::default_params_hash())
        ));
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(
        report.ok,
        "expected supported merkle profile binding success, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_ctc_accepts_supported_lenpref_wire_format_binding() {
    let root = temp_dir("verify-kcir-lenpref-wire");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"]["wireFormatId"] =
            serde_json::Value::String(WIRE_FORMAT_LENPREFIXED_REF_V1.to_string());
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(
        report.ok,
        "expected supported len-prefixed wire format success, got:\n{}",
        report.errors.join("\n")
    );
}

#[test]
fn verify_ctc_rejects_unsupported_wire_format_binding() {
    let root = temp_dir("verify-kcir-wire-unsupported");
    let manifest_path = write_pack_with_profile_anchor(&root, "sha256:aaaaaaaa", 7);
    mutate_manifest_json(&manifest_path, |v| {
        v["profile"]["wireFormatId"] =
            serde_json::Value::String("kcir.wire.unknown.v999".to_string());
    });

    let report = verify_ctc_with_options(&manifest_path, CtcVerifyOptions::default());
    assert!(!report.ok, "expected unsupported wire format failure");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsupported profile wireFormatId")),
        "expected unsupported wireFormatId error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == tbp::verify::error_codes::PROFILE_UNSUPPORTED),
        "expected structured profile unsupported code, got: {:?}",
        report.error_details
    );
}
