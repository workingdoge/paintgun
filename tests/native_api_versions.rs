use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tbp::cert::{build_ctc_manifest, ConflictMode, CtcSummary, NativeApiVersions};
use tbp::compose::{build_compose_manifest, ComposeWitnesses};
use tbp::emit::{KOTLIN_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION};
use tbp::policy::{policy_digest, Policy};
use tbp::resolver::{ResolverDoc, TokenStore};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tbp-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn empty_doc() -> ResolverDoc {
    ResolverDoc {
        name: None,
        version: "2025.10".to_string(),
        description: None,
        sets: HashMap::new(),
        modifiers: HashMap::new(),
        resolution_order: Vec::new(),
        inline_sets: HashMap::new(),
        inline_modifiers: HashMap::new(),
    }
}

fn empty_store() -> TokenStore {
    TokenStore {
        axes: BTreeMap::new(),
        resolved_by_ctx: HashMap::new(),
    }
}

fn empty_summary() -> CtcSummary {
    CtcSummary {
        tokens: 0,
        contexts: 1,
        kan_gaps: 0,
        kan_conflicts: 0,
        kan_inherited: 0,
        bc_violations: 0,
        orthogonality_overlaps: 0,
    }
}

#[test]
fn ctc_manifest_carries_swift_native_api_version() {
    let out = temp_dir("ctc-native-swift");
    let resolver_path = out.join("resolver.json");
    let resolved_path = out.join("resolved.json");
    let swift_path = out.join("tokens.swift");

    fs::write(&resolver_path, "{}").expect("write resolver");
    fs::write(&resolved_path, "{}").expect("write resolved");
    fs::write(&swift_path, "// swift").expect("write swift");

    let manifest = build_ctc_manifest(
        &empty_doc(),
        &resolver_path,
        &empty_store(),
        Some(&Policy::default()),
        ConflictMode::Semantic,
        &resolved_path,
        None,
        Some(&swift_path),
        None,
        None,
        None,
        None,
        empty_summary(),
        "sha256:witnesses".to_string(),
    );

    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions for swift output");
    assert_eq!(native.swift.as_deref(), Some(SWIFT_EMITTER_API_VERSION));
    assert_eq!(native.kotlin, None);
}

#[test]
fn ctc_manifest_carries_kotlin_native_api_version() {
    let out = temp_dir("ctc-native-kotlin");
    let resolver_path = out.join("resolver.json");
    let resolved_path = out.join("resolved.json");
    let kotlin_path = out.join("tokens.kt");

    fs::write(&resolver_path, "{}").expect("write resolver");
    fs::write(&resolved_path, "{}").expect("write resolved");
    fs::write(&kotlin_path, "// kotlin").expect("write kotlin");

    let manifest = build_ctc_manifest(
        &empty_doc(),
        &resolver_path,
        &empty_store(),
        Some(&Policy::default()),
        ConflictMode::Semantic,
        &resolved_path,
        None,
        None,
        Some(&kotlin_path),
        None,
        None,
        None,
        empty_summary(),
        "sha256:witnesses".to_string(),
    );

    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions for kotlin output");
    assert_eq!(native.swift, None);
    assert_eq!(native.kotlin.as_deref(), Some(KOTLIN_EMITTER_API_VERSION));
}

#[test]
fn compose_manifest_preserves_native_api_versions() {
    let policy = Policy::default();
    let witnesses = ComposeWitnesses {
        witness_schema: 1,
        conflict_mode: ConflictMode::Semantic,
        policy_digest: Some(policy_digest(&policy)),
        normalizer_version: None,
        conflicts: Vec::new(),
    };
    let native_versions = Some(NativeApiVersions {
        swift: Some(SWIFT_EMITTER_API_VERSION.to_string()),
        kotlin: None,
    });

    let manifest = build_compose_manifest(
        &[],
        &BTreeMap::new(),
        &policy,
        ConflictMode::Semantic,
        native_versions,
        "sha256:w".to_string(),
        &witnesses,
    )
    .expect("compose manifest");

    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions on compose manifest");
    assert_eq!(native.swift.as_deref(), Some(SWIFT_EMITTER_API_VERSION));
    assert_eq!(native.kotlin, None);
}
