use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, ToolInfo, TrustMetadata,
};
use paintgun::compose::{
    error_codes as compose_error_codes, verify_compose, ComposeManifest, ComposePackEntry,
    ComposeSummary, ComposeWitnesses,
};
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc, ResolverError};
use paintgun::verify::verify_ctc;

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

#[test]
fn resolver_rejects_parent_directory_source_refs() {
    let root = temp_dir("resolver-path-safety");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");

    let outside_tokens = root.join("outside.tokens.json");
    fs::write(&outside_tokens, r#"{"foo":{"$type":"number","$value":1}}"#).expect("outside tokens");

    let resolver_path = workspace.join("resolver.json");
    fs::write(
        &resolver_path,
        r##"{
          "version": "2025.10",
          "sets": {
            "base": {
              "sources": [
                { "$ref": "../outside.tokens.json" }
              ]
            }
          },
          "modifiers": {},
          "resolutionOrder": [{ "$ref": "#/sets/base" }]
        }"##,
    )
    .expect("resolver file");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store(&doc, &resolver_path).expect_err("expected unsafe path rejection");
    match err {
        ResolverError::UnsafePath { path, .. } => {
            assert_eq!(path, "../outside.tokens.json");
        }
        other => panic!("expected UnsafePath error, got {other:?}"),
    }
}

#[test]
fn verify_ctc_rejects_unsafe_manifest_entry_paths() {
    let root = temp_dir("verify-path-safety");
    let dist = root.join("dist");
    fs::create_dir_all(&dist).expect("dist");

    let outside = root
        .parent()
        .expect("temp dir should have parent")
        .join(format!("outside-{}.json", std::process::id()));
    fs::write(&outside, b"{}").expect("outside");

    let resolved_bytes = b"{}";
    fs::write(dist.join("resolved.json"), resolved_bytes).expect("resolved");

    let witnesses_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "witnessSchema": 1,
        "conflictMode": "semantic",
        "policyDigest": "sha256:dummy",
        "gaps": [],
        "conflicts": [],
        "inherited": [],
        "bcViolations": [],
        "orthogonality": []
    }))
    .expect("witnesses json");
    fs::write(dist.join("ctc.witnesses.json"), &witnesses_bytes).expect("witnesses");

    let manifest = CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: "test-pack".to_string(),
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
        backend_artifacts: Vec::new(),
        native_api_versions: None,
        inputs: CtcInputs {
            resolver_spec: ManifestEntry {
                file: format!(
                    "../../{}",
                    outside
                        .file_name()
                        .expect("outside file name")
                        .to_string_lossy()
                ),
                sha256: "sha256:dummy".to_string(),
                size: 2,
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
    let manifest_path = dist.join("ctc.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let report = verify_ctc(&manifest_path, None, false);
    assert!(!report.ok, "verify should fail on unsafe manifest paths");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsafe manifest path ../../outside-")),
        "expected unsafe-path error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == paintgun::verify::error_codes::PATH_UNSAFE),
        "expected structured path safety code, got: {:?}",
        report.error_details
    );
}

#[test]
fn verify_compose_rejects_unsafe_pack_dirs() {
    let root = temp_dir("verify-compose-path-safety");
    let dist = root.join("dist");
    fs::create_dir_all(&dist).expect("dist");

    let witnesses = ComposeWitnesses {
        witness_schema: 1,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some("sha256:dummy".to_string()),
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let witness_bytes = serde_json::to_vec_pretty(&witnesses).expect("witnesses");
    fs::write(dist.join("compose.witnesses.json"), &witness_bytes).expect("write witnesses");

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        trust: TrustMetadata::unsigned(),
        axes: BTreeMap::new(),
        pack_order: vec!["pack-a".to_string()],
        packs: vec![ComposePackEntry {
            name: "pack-a".to_string(),
            dir: "../pack-a".to_string(),
            pack_identity: PackIdentity {
                pack_id: "pack-a".to_string(),
                pack_version: "1.0.0".to_string(),
                content_hash: "sha256:pack".to_string(),
            },
            ctc_manifest: ManifestEntry {
                file: "ctc.manifest.json".to_string(),
                sha256: "sha256:x".to_string(),
                size: 1,
            },
            ctc_witnesses: ManifestEntry {
                file: "ctc.witnesses.json".to_string(),
                sha256: "sha256:y".to_string(),
                size: 1,
            },
            resolved_json: ManifestEntry {
                file: "resolved.json".to_string(),
                sha256: "sha256:z".to_string(),
                size: 1,
            },
            authored_json: None,
        }],
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
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
        witnesses_sha256: sha256_prefixed(&witness_bytes),
    };
    let manifest_path = dist.join("compose.manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize compose manifest"),
    )
    .expect("write compose manifest");

    let report = verify_compose(&manifest_path, None, false, false);
    assert!(!report.ok, "verify-compose should fail on unsafe pack dirs");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsafe pack dir ../pack-a")),
        "expected unsafe pack dir error, got:\n{}",
        report.errors.join("\n")
    );
    assert!(
        report
            .error_details
            .iter()
            .any(|e| e.code == compose_error_codes::PATH_UNSAFE),
        "expected PATH_UNSAFE code, got:\n{:?}",
        report.error_details
    );
}
