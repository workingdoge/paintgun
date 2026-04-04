use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use paintgun::cert::{
    analyze_composability, render_validation_report, ConflictMode, CtcInputs, CtcManifest,
    CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata,
};
use paintgun::compose::{
    analyze_cross_pack_conflicts, render_compose_report, ComposeManifest, ComposeSummary, Pack,
};
use paintgun::dtcg::{DtcgType, DtcgValue, NumLit};
use paintgun::resolver::{
    build_token_store, read_json_file, ResolvedToken, ResolverDoc, TokenStore,
};

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
    make_pack_with_count(name, num.parse::<usize>().expect("numeric fixture"), 1)
}

fn make_pack_with_count(name: &str, start: usize, count: usize) -> Pack {
    let mut resolved_by_ctx = HashMap::new();
    let tokens = (0..count)
        .map(|offset| ResolvedToken {
            path: if count == 1 {
                "color.surface.bg".to_string()
            } else {
                format!("color.surface.bg.{offset:02}")
            },
            ty: DtcgType::Number,
            value: DtcgValue::Num(NumLit((start + offset).to_string())),
            source: "fixture".to_string(),
        })
        .collect();
    resolved_by_ctx.insert("(base)".to_string(), tokens);
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
fn validation_report_is_family_first_and_action_oriented() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");

    let text = render_validation_report(&store, &analysis);
    assert!(text.contains("Action summary:"), "missing action summary");
    assert!(
        text.contains("Errors requiring action:"),
        "missing error heading"
    );
    assert!(
        text.contains("Ambiguous definition [error | direct"),
        "missing family-first conflict section"
    );
    assert!(
        text.contains("What it means:"),
        "missing explanatory lead-in"
    );
    assert!(
        text.contains("Next action:"),
        "missing remediation guidance"
    );
    assert!(
        text.contains("Technical analysis summary:"),
        "missing technical summary"
    );
}

#[test]
fn compose_report_is_family_first_and_action_oriented() {
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

    let text = render_compose_report(&manifest, &witnesses);
    assert!(
        text.contains("Ambiguous definition (cross-pack) [error | direct"),
        "missing family-first compose section"
    );
    assert!(
        text.contains("What it means:"),
        "missing compose explanation"
    );
    assert!(
        text.contains("Next action:"),
        "missing compose action guidance"
    );
    assert!(text.contains("current winner:"), "missing winner context");
    assert!(text.contains("Guardrails:"), "missing guardrail section");
    assert!(text.contains("Rollups:"), "missing rollup section");
}

#[test]
fn large_compose_report_rolls_up_and_truncates_details() {
    let pack_a = make_pack_with_count("pack-a@1.0.0", 1, 60);
    let pack_b = make_pack_with_count("pack-b@2.0.0", 100, 60);
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
            token_paths_union: 60,
            overlapping_token_paths: 60,
            conflicts: witnesses.conflicts.len(),
        },
        witnesses_sha256: "sha256:w".to_string(),
    };

    let text = render_compose_report(&manifest, &witnesses);
    assert!(
        text.contains("Planner budget: warn"),
        "expected planner guardrail warning"
    );
    assert!(
        text.contains("Prefer `--contexts from-contracts`"),
        "expected planner guidance"
    );
    assert!(
        text.contains("Witness budget: warn"),
        "expected witness guardrail warning"
    );
    assert!(text.contains("Token paths:"), "missing token-path rollup");
    assert!(text.contains("Winner packs:"), "missing winner-pack rollup");
    assert!(text.contains("Pack sets:"), "missing pack-set rollup");
    assert!(
        text.contains("(… 35 more; see compose.witnesses.json)"),
        "expected truncated detail hint"
    );
}
