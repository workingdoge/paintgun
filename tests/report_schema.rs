use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

use paintgun::cert::{
    analyze_composability, build_validation_report_json, ConflictMode, CtcInputs, CtcManifest,
    CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata,
};
use paintgun::compose::{
    analyze_cross_pack_conflicts, build_compose_report_json, refresh_compose_report_scale_metadata,
    ComposeManifest, ComposeSummary, Pack,
};
use paintgun::dtcg::{DtcgType, DtcgValue, NumLit};
use paintgun::resolver::{
    build_token_store, read_json_file, ResolvedToken, ResolverDoc, TokenStore,
};

fn report_schema() -> JSONSchema {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema_path = root.join("schemas/report.schema.json");
    let schema_bytes = fs::read(&schema_path).expect("read report schema");
    let schema_json: Value = serde_json::from_slice(&schema_bytes).expect("parse report schema");
    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .expect("compile report schema")
}

fn backend_artifacts_json() -> Value {
    serde_json::json!([
        {
            "backendId": "web-css-vars",
            "kind": "tokenStylesheet",
            "file": "tokens.vars.css",
            "sha256": "sha256:dummy-css",
            "size": 42
        },
        {
            "backendId": "swift-tokens",
            "kind": "primaryTokenOutput",
            "file": "Tokens.swift",
            "sha256": "sha256:dummy-swift",
            "size": 84,
            "apiVersion": "paintgun-swift-v1"
        }
    ])
}

#[test]
fn pack_report_matches_schema() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");
    let mut report = build_validation_report_json(&analysis);
    report
        .as_object_mut()
        .expect("report object")
        .insert("backendArtifacts".to_string(), backend_artifacts_json());

    report_schema().validate(&report).unwrap_or_else(|errs| {
        panic!(
            "pack report schema errors:\n{}",
            errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
        )
    });
}

fn dummy_manifest(name: &str) -> CtcManifest {
    CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: name.to_string(),
            pack_version: "2025.10".to_string(),
            content_hash: format!("sha256:{name}-resolved"),
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
                file: "resolver.json".to_string(),
                sha256: "sha256:dummy".to_string(),
                size: 1,
            },
            token_docs: Vec::new(),
        },
        outputs: CtcOutputs {
            resolved_json: ManifestEntry {
                file: format!("{name}.resolved.json"),
                sha256: format!("sha256:{name}-resolved"),
                size: 1,
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
        witnesses_sha256: "sha256:w".to_string(),
        required_artifacts: Vec::new(),
        admissibility_witnesses_sha256: None,
    }
}

fn make_pack(name: &str, num: &str) -> Pack {
    let mut resolved_by_ctx = HashMap::new();
    resolved_by_ctx.insert(
        "(base)".to_string(),
        vec![ResolvedToken {
            path: "color.surface.bg".to_string(),
            ty: DtcgType::Number,
            value: DtcgValue::Num(NumLit(num.to_string())),
            source: "fixture".to_string(),
        }],
    );
    Pack {
        name: name.to_string(),
        dir: PathBuf::from(format!("/tmp/{name}")),
        ctc_manifest: dummy_manifest(name),
        ctc_witnesses: None,
        store: TokenStore {
            axes: BTreeMap::new(),
            resolved_by_ctx,
        },
        authored_by_token: None,
    }
}

#[test]
fn compose_report_matches_schema() {
    let pack_a = make_pack("pack-a@1.0.0", "1");
    let pack_b = make_pack("pack-b@2.0.0", "2");
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &BTreeMap::new());

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        trust: TrustMetadata::unsigned(),
        axes: BTreeMap::new(),
        pack_order: vec!["pack-a@1.0.0".to_string(), "pack-b@2.0.0".to_string()],
        packs: Vec::new(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        backend_artifacts: vec![
            paintgun::cert::BackendArtifactDescriptor {
                backend_id: "web-css-vars".to_string(),
                kind: paintgun::cert::BackendArtifactDescriptorKind::TokenStylesheet,
                entry: ManifestEntry {
                    file: "tokens.vars.css".to_string(),
                    sha256: "sha256:dummy-css".to_string(),
                    size: 42,
                },
                api_version: None,
            },
            paintgun::cert::BackendArtifactDescriptor {
                backend_id: "swift-tokens".to_string(),
                kind: paintgun::cert::BackendArtifactDescriptorKind::PrimaryTokenOutput,
                entry: ManifestEntry {
                    file: "Tokens.swift".to_string(),
                    sha256: "sha256:dummy-swift".to_string(),
                    size: 84,
                },
                api_version: Some("paintgun-swift-v1".to_string()),
            },
        ],
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 2,
            contexts: 1,
            token_paths_union: 1,
            overlapping_token_paths: 1,
            conflicts: witnesses.conflicts.len(),
        },
        witnesses_sha256: "sha256:w".to_string(),
    };

    let report = build_compose_report_json(&manifest, &witnesses);
    assert_eq!(report["guardrails"]["planner"]["status"], "ok");
    assert_eq!(report["guardrails"]["planner"]["packCount"], 2);
    assert_eq!(report["guardrails"]["witnesses"]["detailLimit"], 25);
    assert_eq!(report["rollups"]["tokenPaths"][0]["count"], 1);
    report_schema().validate(&report).unwrap_or_else(|errs| {
        panic!(
            "compose report schema errors:\n{}",
            errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
        )
    });
}

#[test]
fn compose_report_scale_metadata_refresh_preserves_schema() {
    let pack_a = make_pack("pack-a@1.0.0", "1");
    let pack_b = make_pack("pack-b@2.0.0", "2");
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &BTreeMap::new());

    let manifest = ComposeManifest {
        compose_version: "0.1".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        trust: TrustMetadata::unsigned(),
        axes: BTreeMap::new(),
        pack_order: vec!["pack-a@1.0.0".to_string(), "pack-b@2.0.0".to_string()],
        packs: Vec::new(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-typed-structural".to_string(),
            policy_digest: Some("sha256:dummy".to_string()),
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        backend_artifacts: Vec::new(),
        native_api_versions: None,
        summary: ComposeSummary {
            packs: 24,
            contexts: 80,
            token_paths_union: 1,
            overlapping_token_paths: 1,
            conflicts: witnesses.conflicts.len(),
        },
        witnesses_sha256: "sha256:w".to_string(),
    };

    let mut report = build_compose_report_json(&manifest, &witnesses);
    report
        .as_object_mut()
        .expect("compose report object")
        .insert(
            "plannerTrace".to_string(),
            serde_json::json!({
                "version": 1,
                "scope": "compose",
                "mode": "from-contracts",
                "axisUniverse": ["theme", "density"],
                "relevantAxes": ["theme"],
                "contractTokens": ["color.surface.bg"],
                "counts": {
                    "universe": 108,
                    "analysisIncluded": 40,
                    "resolverIncluded": 40,
                    "excluded": 68
                },
                "truncated": {
                    "included": 0,
                    "resolverIncluded": 0,
                    "excluded": 0
                },
                "included": [
                    { "context": "(base)", "rule": "mode:from-contracts", "source": "analysis" }
                ],
                "resolverIncluded": [
                    { "context": "theme:dark", "rule": "required-for-supporting-ops", "source": "resolver" }
                ],
                "excluded": [
                    { "context": "theme:dark,density:compact", "rule": "not-selected-by-mode", "source": "analysis" }
                ]
            }),
        );
    refresh_compose_report_scale_metadata(&mut report, &manifest, &witnesses);

    assert_eq!(report["guardrails"]["planner"]["status"], "warn");
    assert_eq!(report["guardrails"]["planner"]["analysisIncluded"], 40);
    assert_eq!(report["guardrails"]["planner"]["analysisUniverse"], 108);
    assert_eq!(report["guardrails"]["witnesses"]["status"], "ok");
    report_schema().validate(&report).unwrap_or_else(|errs| {
        panic!(
            "compose report scale metadata schema errors:\n{}",
            errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
        )
    });
}

#[test]
fn planner_trace_extension_matches_schema() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");
    let mut report = build_validation_report_json(&analysis);
    report
        .as_object_mut()
        .expect("report object")
        .insert(
            "plannerTrace".to_string(),
            serde_json::json!({
                "version": 1,
                "scope": "build",
                "mode": "from-contracts",
                "axisUniverse": ["theme", "density"],
                "relevantAxes": ["theme"],
                "contractTokens": ["color.surface.bg"],
                "counts": {
                    "universe": 9,
                    "analysisIncluded": 4,
                    "resolverIncluded": 9,
                    "excluded": 5
                },
                "truncated": {
                    "included": 0,
                    "resolverIncluded": 0,
                    "excluded": 0
                },
                "included": [
                    { "context": "(base)", "rule": "mode:from-contracts", "source": "analysis" }
                ],
                "resolverIncluded": [
                    { "context": "theme:dark", "rule": "required-for-supporting-ops", "source": "resolver" }
                ],
                "excluded": [
                    { "context": "theme:dark,density:compact", "rule": "not-selected-by-mode", "source": "analysis" }
                ]
            }),
        );

    report_schema().validate(&report).unwrap_or_else(|errs| {
        panic!(
            "planner trace schema errors:\n{}",
            errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
        )
    });
}
