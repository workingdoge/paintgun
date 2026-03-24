use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use paintgun::cert::{
    ConflictMode, CtcConflictCandidate, CtcConflictWitness, CtcInheritedWitness, CtcInputs,
    CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, CtcWitnesses, ManifestEntry, PackIdentity,
    ToolInfo, TrustMetadata,
};
use paintgun::compose::{analyze_cross_pack_conflicts, Pack};
use paintgun::dtcg::{DtcgType, DtcgValue, NumLit, TypedValue};
use paintgun::provenance::{AuthoredValue, TokenProvenance};
use paintgun::resolver::{ResolvedToken, TokenStore};
use paintgun::util::sha256_hex;

fn dummy_manifest(resolver_sha: &str) -> CtcManifest {
    CtcManifest {
        ctc_version: "0.1".to_string(),
        kcir_version: "2".to_string(),
        tool: ToolInfo {
            name: "paintgun".to_string(),
            version: "0.1.0".to_string(),
        },
        spec: "2025.10".to_string(),
        pack_identity: PackIdentity {
            pack_id: "local-pack".to_string(),
            pack_version: "2025.10".to_string(),
            content_hash: "sha256:resolved".to_string(),
        },
        trust: TrustMetadata::unsigned(),
        profile: Some(paintgun::kcir_v2::default_kcir_profile_binding()),
        axes: BTreeMap::new(),
        semantics: CtcSemantics {
            eq_value_id: "dtcg-2025.10-structural".to_string(),
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
                file: "resolved.json".to_string(),
                sha256: "sha256:resolved".to_string(),
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

fn digest_number_value(value_num: &str) -> String {
    let tv = TypedValue {
        ty: DtcgType::Number,
        value: DtcgValue::Num(NumLit(value_num.to_string())),
    };
    format!(
        "sha256:{}",
        sha256_hex(tv.to_canonical_json_string().as_bytes())
    )
}

fn dummy_witnesses(value_num: &str) -> CtcWitnesses {
    CtcWitnesses {
        witness_schema: 1,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some("sha256:dummy-policy".to_string()),
        normalizer_version: None,
        gaps: Vec::new(),
        conflicts: vec![CtcConflictWitness {
            witness_id: "ctc-conflict-1".to_string(),
            token_path: "color.surface.bg".to_string(),
            target: "(base)".to_string(),
            candidates: vec![CtcConflictCandidate {
                source_context: "(base)".to_string(),
                source_id: "base".to_string(),
                resolution_layer_id: "set:foundation".to_string(),
                resolution_rank: 0,
                pack_id: "local-pack".to_string(),
                pack_version: None,
                pack_hash: "sha256:pack".to_string(),
                file_path: "tokens/base.tokens.json".to_string(),
                file_hash: "sha256:file".to_string(),
                json_pointer: "/color/surface/bg/$value".to_string(),
                value_json: value_num.to_string(),
                value_digest: digest_number_value(value_num),
            }],
        }],
        inherited: vec![CtcInheritedWitness {
            witness_id: "ctc-inherited-1".to_string(),
            token_path: "color.surface.bg".to_string(),
            target: "(base)".to_string(),
            inherited_from: vec!["(base)".to_string()],
            sources: Vec::new(),
            resolved_value_json: value_num.to_string(),
            resolved_value_digest: digest_number_value(value_num),
        }],
        bc_violations: Vec::new(),
        orthogonality: Vec::new(),
    }
}

fn make_pack(name: &str, value_num: &str, resolver_sha: &str) -> Pack {
    let mut resolved_by_ctx = HashMap::new();
    resolved_by_ctx.insert(
        "(base)".to_string(),
        vec![ResolvedToken {
            path: "color.surface.bg".to_string(),
            ty: DtcgType::Number,
            value: DtcgValue::Num(NumLit(value_num.to_string())),
            source: "fixture".to_string(),
        }],
    );

    let store = TokenStore {
        axes: BTreeMap::new(),
        resolved_by_ctx,
    };

    let mut by_ctx = HashMap::new();
    by_ctx.insert(
        "(base)".to_string(),
        AuthoredValue::new(
            DtcgType::Number,
            DtcgValue::Num(NumLit(value_num.to_string())),
            TokenProvenance {
                source_id: "base".to_string(),
                resolution_layer_id: None,
                resolution_rank: None,
                pack_id: None,
                pack_version: None,
                pack_hash: None,
                file_path: Some("tokens/base.tokens.json".to_string()),
                file_hash: Some("sha256:file".to_string()),
                json_pointer: Some("/color/surface/bg/$value".to_string()),
            },
        ),
    );

    let mut authored_by_token = HashMap::new();
    authored_by_token.insert("color.surface.bg".to_string(), by_ctx);

    Pack {
        name: name.to_string(),
        dir: PathBuf::from(format!("/tmp/{name}")),
        ctc_manifest: dummy_manifest(resolver_sha),
        ctc_witnesses: Some(dummy_witnesses(value_num)),
        store,
        authored_by_token: Some(authored_by_token),
    }
}

fn make_pack_without_authored(name: &str, value_num: &str, resolver_sha: &str) -> Pack {
    let mut p = make_pack(name, value_num, resolver_sha);
    p.authored_by_token = None;
    p
}

#[test]
fn compose_sources_stamp_pack_identity() {
    let pack_a = make_pack("pack-a@1.2.3", "1", "sha256:packa");
    let pack_b = make_pack("pack-b@2.0.0", "2", "sha256:packb");

    let axes = BTreeMap::new();
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &axes);

    let conflict = witnesses
        .conflicts
        .first()
        .expect("expected a cross-pack conflict witness");
    let cand = conflict
        .candidates
        .first()
        .expect("expected candidate list to be non-empty");
    let src = cand
        .sources
        .first()
        .expect("expected candidate source provenance");

    assert!(src.provenance.pack_id.is_some(), "packId should be stamped");
    assert!(
        src.provenance.pack_hash.is_some(),
        "packHash should be stamped"
    );
    assert!(
        src.provenance.file_path.is_some(),
        "filePath should be present"
    );
    assert!(
        src.provenance.file_hash.is_some(),
        "fileHash should be present"
    );
    assert!(
        src.provenance.json_pointer.is_some(),
        "jsonPointer should be present"
    );
    assert!(
        src.provenance.resolution_layer_id.is_some(),
        "resolutionLayerId should be present"
    );
    assert!(
        src.provenance.resolution_rank.is_some(),
        "resolutionRank should be present"
    );
    assert!(
        !cand.inherited_from.is_empty(),
        "expected inheritedFrom linkage to per-pack witnesses"
    );
    assert!(
        cand.inherited_from
            .iter()
            .any(|r| r.witness_type == "inherited" && r.witness_id.as_str() == "ctc-inherited-1"),
        "expected inheritedFrom to include inherited witness ref"
    );
    assert!(
        cand.inherited_from
            .iter()
            .any(|r| r.witness_type == "conflict" && r.witness_id.as_str() == "ctc-conflict-1"),
        "expected inheritedFrom to include conflict witness ref"
    );
}

#[test]
fn compose_sources_canonicalize_pack_name_identity_variants() {
    let hex = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
    let pack_a = make_pack(&format!("pack-a@1.2.3+sha256_{hex}"), "1", "sha256:packa");
    let pack_b = make_pack("pack-b@2.0.0", "2", "sha256:packb");

    let axes = BTreeMap::new();
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &axes);

    let conflict = witnesses
        .conflicts
        .first()
        .expect("expected a cross-pack conflict witness");
    let cand = conflict
        .candidates
        .first()
        .expect("expected candidate list to be non-empty");
    let src = cand
        .sources
        .first()
        .expect("expected candidate source provenance");

    assert_eq!(src.provenance.pack_id.as_deref(), Some("pack-a"));
    assert_eq!(src.provenance.pack_version.as_deref(), Some("1.2.3"));
    assert_eq!(
        src.provenance.pack_hash.as_deref(),
        Some("sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
    );
}

#[test]
fn compose_sources_fallback_when_authored_missing() {
    let pack_a = make_pack_without_authored("pack-a@1.2.3", "1", "sha256:packa");
    let pack_b = make_pack_without_authored("pack-b@2.0.0", "2", "sha256:packb");

    let axes = BTreeMap::new();
    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &axes);

    let conflict = witnesses
        .conflicts
        .first()
        .expect("expected a cross-pack conflict witness");
    let cand = conflict
        .candidates
        .first()
        .expect("expected candidate list to be non-empty");
    let src = cand
        .sources
        .first()
        .expect("expected fallback source provenance");

    assert!(src.provenance.pack_id.is_some(), "packId should be present");
    assert!(
        src.provenance.pack_hash.is_some(),
        "packHash should be present"
    );
    assert!(
        src.provenance.file_path.is_some(),
        "filePath should be present"
    );
    assert!(
        src.provenance.file_hash.is_some(),
        "fileHash should be present"
    );
}
