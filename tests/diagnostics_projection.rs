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
    analyze_cross_pack_conflicts, build_compose_report_json, ComposeManifest, ComposeSummary, Pack,
};
use paintgun::diagnostics::build_editor_diagnostics_projection_json;
use paintgun::dtcg::{DtcgType, DtcgValue, NumLit};
use paintgun::resolver::{
    build_token_store, read_json_file, ResolvedToken, ResolverDoc, TokenStore,
};

fn diagnostics_schema() -> JSONSchema {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema_path = root.join("schemas/diagnostics.schema.json");
    let schema_bytes = fs::read(&schema_path).expect("read diagnostics schema");
    let schema_json: Value =
        serde_json::from_slice(&schema_bytes).expect("parse diagnostics schema");
    JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .expect("compile diagnostics schema")
}

fn backend_artifacts_json() -> Value {
    serde_json::json!([
        {
            "backendId": "web-tokens-ts",
            "kind": "primaryTokenOutput",
            "file": "tokens.ts",
            "sha256": "sha256:deadbeef",
            "size": 42
        }
    ])
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
fn pack_diagnostics_projection_matches_schema() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/quickstart/failing.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");
    let mut report = build_validation_report_json(&analysis);
    report
        .as_object_mut()
        .expect("report object")
        .insert("backendArtifacts".to_string(), backend_artifacts_json());

    let diagnostics =
        build_editor_diagnostics_projection_json(&report, "validation.json").expect("projection");

    diagnostics_schema()
        .validate(&diagnostics)
        .unwrap_or_else(|errs| {
            panic!(
                "pack diagnostics schema errors:\n{}",
                errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
            )
        });

    assert_eq!(diagnostics["projectionKind"], "editorDiagnostics");
    assert_eq!(diagnostics["sourceReport"]["file"], "validation.json");
    assert_eq!(diagnostics["summary"]["clean"], false);
    assert_eq!(diagnostics["records"][0]["familyId"], "missing-definition");
    assert_eq!(
        diagnostics["records"][0]["nextAction"],
        "Author an explicit value in the intended winning layer or context."
    );
}

#[test]
fn compose_diagnostics_projection_matches_schema() {
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
            packs: 2,
            contexts: 1,
            token_paths_union: 1,
            overlapping_token_paths: 1,
            conflicts: witnesses.conflicts.len(),
        },
        witnesses_sha256: "sha256:w".to_string(),
    };

    let report = build_compose_report_json(&manifest, &witnesses);
    let diagnostics = build_editor_diagnostics_projection_json(&report, "compose.report.json")
        .expect("projection");

    diagnostics_schema()
        .validate(&diagnostics)
        .unwrap_or_else(|errs| {
            panic!(
                "compose diagnostics schema errors:\n{}",
                errs.map(|e| e.to_string()).collect::<Vec<_>>().join("\n")
            )
        });

    assert_eq!(diagnostics["reportKind"], "compose");
    assert_eq!(diagnostics["sourceReport"]["file"], "compose.report.json");
    assert_eq!(
        diagnostics["records"][0]["familyId"],
        "ambiguous-definition"
    );
}
