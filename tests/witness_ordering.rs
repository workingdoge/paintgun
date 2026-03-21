use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use tbp::cert::{
    analyze_composability, ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics,
    CtcSummary, ManifestEntry, PackIdentity, ToolInfo, TrustMetadata,
};
use tbp::compose::{analyze_cross_pack_conflicts, Pack};
use tbp::dtcg::{DtcgType, DtcgValue, NumLit};
use tbp::resolver::{build_token_store, read_json_file, ResolvedToken, ResolverDoc, TokenStore};

fn assert_sorted_by<T, F>(items: &[T], mut cmp: F, label: &str)
where
    F: FnMut(&T, &T) -> Ordering,
{
    for pair in items.windows(2) {
        assert!(
            cmp(&pair[0], &pair[1]) != Ordering::Greater,
            "{label} not in canonical order"
        );
    }
}

#[test]
fn pack_witnesses_have_canonical_ordering() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    assert_sorted_by(
        &analysis.witnesses.gaps,
        |a, b| {
            a.token_path
                .cmp(&b.token_path)
                .then(a.target.cmp(&b.target))
                .then(a.witness_id.cmp(&b.witness_id))
        },
        "gaps",
    );
    for g in &analysis.witnesses.gaps {
        assert_sorted_by(
            &g.authored_sources,
            |a, b| {
                a.source_context
                    .cmp(&b.source_context)
                    .then(a.resolution_rank.cmp(&b.resolution_rank))
                    .then(a.source_id.cmp(&b.source_id))
                    .then(a.file_path.cmp(&b.file_path))
                    .then(a.json_pointer.cmp(&b.json_pointer))
                    .then(a.value_digest.cmp(&b.value_digest))
            },
            "gap.authored_sources",
        );
    }

    assert_sorted_by(
        &analysis.witnesses.conflicts,
        |a, b| {
            a.token_path
                .cmp(&b.token_path)
                .then(a.target.cmp(&b.target))
                .then(a.witness_id.cmp(&b.witness_id))
        },
        "conflicts",
    );
    for c in &analysis.witnesses.conflicts {
        assert_sorted_by(
            &c.candidates,
            |a, b| {
                a.source_context
                    .cmp(&b.source_context)
                    .then(a.resolution_rank.cmp(&b.resolution_rank))
                    .then(a.source_id.cmp(&b.source_id))
                    .then(a.file_path.cmp(&b.file_path))
                    .then(a.json_pointer.cmp(&b.json_pointer))
                    .then(a.value_digest.cmp(&b.value_digest))
            },
            "conflict.candidates",
        );
    }

    assert_sorted_by(
        &analysis.witnesses.inherited,
        |a, b| {
            a.token_path
                .cmp(&b.token_path)
                .then(a.target.cmp(&b.target))
                .then(a.witness_id.cmp(&b.witness_id))
        },
        "inherited",
    );
    for i in &analysis.witnesses.inherited {
        assert_sorted_by(
            &i.sources,
            |a, b| {
                a.source_context
                    .cmp(&b.source_context)
                    .then(a.resolution_rank.cmp(&b.resolution_rank))
                    .then(a.source_id.cmp(&b.source_id))
                    .then(a.file_path.cmp(&b.file_path))
                    .then(a.json_pointer.cmp(&b.json_pointer))
                    .then(a.value_digest.cmp(&b.value_digest))
            },
            "inherited.sources",
        );
    }

    assert_sorted_by(
        &analysis.witnesses.bc_violations,
        |a, b| {
            a.token_path
                .cmp(&b.token_path)
                .then(a.axis_a.cmp(&b.axis_a))
                .then(a.value_a.cmp(&b.value_a))
                .then(a.axis_b.cmp(&b.axis_b))
                .then(a.value_b.cmp(&b.value_b))
                .then(a.witness_id.cmp(&b.witness_id))
        },
        "bcViolations",
    );

    assert_sorted_by(
        &analysis.witnesses.orthogonality,
        |a, b| {
            a.axis_a
                .cmp(&b.axis_a)
                .then(a.axis_b.cmp(&b.axis_b))
                .then(a.witness_id.cmp(&b.witness_id))
        },
        "orthogonality",
    );
}

#[test]
fn pack_witnesses_are_deterministic_across_runs() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    let a = analyze_composability(&doc, &store, &resolver_path).expect("analysis A");
    let b = analyze_composability(&doc, &store, &resolver_path).expect("analysis B");
    assert_eq!(a.summary.tokens, b.summary.tokens, "sanity check");
    let a_json = serde_json::to_value(&a.witnesses).expect("serialize A witnesses");
    let b_json = serde_json::to_value(&b.witnesses).expect("serialize B witnesses");
    assert_eq!(a_json, b_json, "witness payload drifted across runs");
}

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
fn compose_witnesses_are_deterministic_and_sorted() {
    let pack_a = make_pack("pack-a@1.0.0", "1");
    let pack_b = make_pack("pack-b@2.0.0", "2");
    let a = analyze_cross_pack_conflicts(&[pack_a.clone(), pack_b.clone()], &BTreeMap::new());
    let b = analyze_cross_pack_conflicts(&[pack_a, pack_b], &BTreeMap::new());

    let a_json = serde_json::to_value(&a).expect("serialize compose A witnesses");
    let b_json = serde_json::to_value(&b).expect("serialize compose B witnesses");
    assert_eq!(a_json, b_json, "compose witness payload drifted");
    assert_sorted_by(
        &a.conflicts,
        |x, y| {
            x.token_path
                .cmp(&y.token_path)
                .then(x.context.cmp(&y.context))
                .then(x.witness_id.cmp(&y.witness_id))
        },
        "compose.conflicts",
    );
}
