use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use tbp::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, ToolInfo, TrustMetadata,
};
use tbp::compose::{analyze_cross_pack_conflicts_with_mode, Pack};
use tbp::dtcg::{DtcgDuration, DtcgType, DtcgValue, DurationUnit, NumLit};
use tbp::policy::Policy;
use tbp::resolver::{ResolvedToken, TokenStore};

fn dummy_manifest(name: &str, resolver_sha: &str) -> CtcManifest {
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
            policy_digest: None,
            conflict_mode: ConflictMode::Semantic,
            normalizer_version: None,
        },
        native_api_versions: None,
        inputs: CtcInputs {
            resolver_spec: ManifestEntry {
                file: "resolver.json".to_string(),
                sha256: resolver_sha.to_string(),
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
        witnesses_sha256: "sha256:witnesses".to_string(),
        required_artifacts: Vec::new(),
        admissibility_witnesses_sha256: None,
    }
}

fn make_pack(name: &str, value: DtcgDuration, resolver_sha: &str) -> Pack {
    let mut resolved_by_ctx = HashMap::new();
    resolved_by_ctx.insert(
        "(base)".to_string(),
        vec![ResolvedToken {
            path: "motion.duration.fast".to_string(),
            ty: DtcgType::Duration,
            value: DtcgValue::Duration(value),
            source: "fixture".to_string(),
        }],
    );

    let store = TokenStore {
        axes: BTreeMap::new(),
        resolved_by_ctx,
    };

    Pack {
        name: name.to_string(),
        dir: PathBuf::from(format!("/tmp/{name}")),
        ctc_manifest: dummy_manifest(name, resolver_sha),
        ctc_witnesses: None,
        store,
        authored_by_token: None,
    }
}

#[test]
fn compose_conflict_mode_normalized_can_resolve_duration_conflicts() {
    let pack_a = make_pack(
        "pack-a@1.0.0",
        DtcgDuration {
            value: NumLit("1".to_string()),
            unit: DurationUnit::S,
        },
        "sha256:packa",
    );
    let pack_b = make_pack(
        "pack-b@2.0.0",
        DtcgDuration {
            value: NumLit("1000".to_string()),
            unit: DurationUnit::Ms,
        },
        "sha256:packb",
    );

    let semantic = analyze_cross_pack_conflicts_with_mode(
        &[pack_a.clone(), pack_b.clone()],
        &BTreeMap::new(),
        ConflictMode::Semantic,
        &Policy::default(),
    );
    assert_eq!(
        semantic.conflicts.len(),
        1,
        "expected semantic compose conflict"
    );

    let policy: Policy = serde_json::from_value(serde_json::json!({
        "duration": { "prefer": "ms" }
    }))
    .expect("policy");
    let normalized = analyze_cross_pack_conflicts_with_mode(
        &[pack_a, pack_b],
        &BTreeMap::new(),
        ConflictMode::Normalized,
        &policy,
    );
    assert!(
        normalized.conflicts.is_empty(),
        "normalized compose mode should suppress conflict for equivalent durations"
    );
}
