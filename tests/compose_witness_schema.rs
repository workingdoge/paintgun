use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

use paintgun::cert::{
    ConflictMode, CtcInputs, CtcManifest, CtcOutputs, CtcSemantics, CtcSummary, ManifestEntry,
    PackIdentity, ToolInfo, TrustMetadata,
};
use paintgun::compose::{analyze_cross_pack_conflicts, Pack, COMPOSE_WITNESS_SCHEMA_VERSION};
use paintgun::dtcg::{DtcgType, DtcgValue, NumLit};
use paintgun::resolver::{ResolvedToken, TokenStore};

fn dummy_manifest(name: &str, resolver_sha: &str) -> CtcManifest {
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
fn compose_witnesses_match_schema() {
    let pack_a = make_pack("pack-a@1.0.0", "1", "sha256:packa");
    let pack_b = make_pack("pack-b@2.0.0", "2", "sha256:packb");

    let witnesses = analyze_cross_pack_conflicts(&[pack_a, pack_b], &BTreeMap::new());
    assert_eq!(
        witnesses.witness_schema, COMPOSE_WITNESS_SCHEMA_VERSION,
        "compose witnesses should carry current schema version marker"
    );
    assert_eq!(
        witnesses.conflict_mode.to_string(),
        "semantic",
        "default compose witness conflict mode should be semantic"
    );
    assert!(
        witnesses
            .policy_digest
            .as_deref()
            .unwrap_or("")
            .starts_with("sha256:"),
        "compose witnesses should include policyDigest"
    );
    let witnesses_json = serde_json::to_value(&witnesses).expect("serialize compose witnesses");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let schema_path = root.join("schemas/compose.witness.schema.json");
    let schema_bytes = fs::read(&schema_path).expect("read schema file");
    let schema_json: Value = serde_json::from_slice(&schema_bytes).expect("parse schema json");

    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft7)
        .compile(&schema_json)
        .expect("compile schema");

    let errs: Vec<String> = match compiled.validate(&witnesses_json) {
        Ok(()) => Vec::new(),
        Err(iter) => iter.map(|e| e.to_string()).collect(),
    };

    assert!(
        errs.is_empty(),
        "compose witness schema validation failed ({} errors):\n{}",
        errs.len(),
        errs.join("\n")
    );
}
