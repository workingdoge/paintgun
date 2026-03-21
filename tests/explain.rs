use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use tbp::cert::{
    analyze_composability, ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics,
    CtcSummary, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata,
};
use tbp::compose::{analyze_cross_pack_conflicts, Pack};
use tbp::dtcg::{DtcgType, DtcgValue, NumLit};
use tbp::explain::{explain_compose_witness, explain_ctc_witness};
use tbp::ids::WitnessId;
use tbp::resolver::{build_token_store, read_json_file, ResolvedToken, ResolverDoc, TokenStore};

fn dummy_manifest(name: &str) -> CtcManifest {
    CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "tbp-rs".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: name.to_string(),
            pack_version: "2025.10".to_string(),
            content_hash: format!("sha256:{name}-resolved"),
        },
        trust: TrustMetadata::unsigned(),
        profile: Some(tbp::kcir_v2::default_kcir_profile_binding()),
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
fn explain_conflict_includes_file_and_pointer() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");
    let witness = analysis
        .witnesses
        .conflicts
        .first()
        .expect("expected conflict witness");

    let text = explain_ctc_witness(
        &analysis.witnesses,
        &WitnessId::from(witness.witness_id.as_str()),
        "dist/ctc.witnesses.json",
    )
    .expect("expected explanation");
    assert!(text.contains("Fix recipe:"), "missing fix recipe");
    assert!(
        text.contains("Primary location:"),
        "missing location section"
    );
    assert!(text.contains("/"), "expected JSON pointer in explanation");
    assert!(
        text.contains("Type: conflict"),
        "wrong witness type explanation"
    );
}

#[test]
fn explain_compose_conflict_includes_file_and_pointer() {
    let pack_a = make_pack("pack-a@1.0.0", "1");
    let pack_b = make_pack("pack-b@2.0.0", "2");
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &BTreeMap::new());
    let witness = witnesses
        .conflicts
        .first()
        .expect("expected compose conflict");
    let text = explain_compose_witness(
        &witnesses,
        &WitnessId::from(witness.witness_id.as_str()),
        "dist-compose/compose.witnesses.json",
    )
    .expect("expected compose explanation");
    assert!(text.contains("Type: composeConflict"), "wrong compose type");
    assert!(text.contains("Fix recipe:"), "missing compose fix");
    assert!(
        text.contains("Primary location:"),
        "missing compose location"
    );
    assert!(text.contains("/$value"), "expected JSON pointer");
}

#[test]
fn explain_returns_none_for_unknown_witness() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("analysis");

    let got = explain_ctc_witness(
        &analysis.witnesses,
        &WitnessId::from("does-not-exist"),
        "dist/ctc.witnesses.json",
    );
    assert!(got.is_none(), "unknown witness should return None");
}
