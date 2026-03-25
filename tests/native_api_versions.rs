use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::cert::{
    build_ctc_manifest, legacy_native_api_versions_from_backend_artifacts,
    BackendArtifactDescriptor, BackendArtifactDescriptorKind, ConflictMode, CtcSummary,
    ManifestEntry, NativeApiVersions,
};
use paintgun::compose::{build_compose_manifest, ComposeWitnesses};
use paintgun::emit::{ANDROID_COMPOSE_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION};
use paintgun::policy::{policy_digest, Policy};
use paintgun::resolver::{ResolverDoc, TokenStore};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
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

fn manifest_entry(path: &Path) -> ManifestEntry {
    let bytes = fs::read(path).expect("read artifact");
    let file = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("artifact file name")
        .to_string();
    ManifestEntry {
        file,
        sha256: format!("sha256:{}", paintgun::util::sha256_hex(&bytes)),
        size: bytes.len() as u64,
    }
}

fn backend_artifact(
    backend_id: &str,
    kind: BackendArtifactDescriptorKind,
    path: &Path,
    api_version: Option<&str>,
) -> BackendArtifactDescriptor {
    BackendArtifactDescriptor {
        backend_id: backend_id.to_string(),
        kind,
        entry: manifest_entry(path),
        api_version: api_version.map(str::to_string),
    }
}

#[test]
fn ctc_manifest_carries_backend_artifacts_and_swift_native_api_version() {
    let out = temp_dir("ctc-native-swift");
    let resolver_path = out.join("resolver.json");
    let resolved_path = out.join("resolved.json");
    let swift_path = out.join("tokens.swift");

    fs::write(&resolver_path, "{}").expect("write resolver");
    fs::write(&resolved_path, "{}").expect("write resolved");
    fs::write(&swift_path, "// swift").expect("write swift");
    let backend_artifacts = vec![
        backend_artifact(
            "swift-tokens",
            BackendArtifactDescriptorKind::PrimaryTokenOutput,
            &swift_path,
            Some(SWIFT_EMITTER_API_VERSION),
        ),
        backend_artifact(
            "swift-tokens",
            BackendArtifactDescriptorKind::PackageSource,
            &swift_path,
            Some(SWIFT_EMITTER_API_VERSION),
        ),
    ];

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
        backend_artifacts.clone(),
        empty_summary(),
        "sha256:witnesses".to_string(),
    );

    assert_eq!(manifest.backend_artifacts, backend_artifacts);
    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions for swift output");
    assert_eq!(native.swift.as_deref(), Some(SWIFT_EMITTER_API_VERSION));
    assert_eq!(native.kotlin, None);
}

#[test]
fn ctc_manifest_carries_backend_artifacts_and_android_native_api_version() {
    let out = temp_dir("ctc-native-android");
    let resolver_path = out.join("resolver.json");
    let resolved_path = out.join("resolved.json");
    let android_path = out.join("tokens.kt");

    fs::write(&resolver_path, "{}").expect("write resolver");
    fs::write(&resolved_path, "{}").expect("write resolved");
    fs::write(&android_path, "// android").expect("write android source");
    let backend_artifacts = vec![
        backend_artifact(
            "android-compose-tokens",
            BackendArtifactDescriptorKind::PrimaryTokenOutput,
            &android_path,
            Some(ANDROID_COMPOSE_EMITTER_API_VERSION),
        ),
        backend_artifact(
            "android-compose-tokens",
            BackendArtifactDescriptorKind::PackageSource,
            &android_path,
            Some(ANDROID_COMPOSE_EMITTER_API_VERSION),
        ),
    ];

    let manifest = build_ctc_manifest(
        &empty_doc(),
        &resolver_path,
        &empty_store(),
        Some(&Policy::default()),
        ConflictMode::Semantic,
        &resolved_path,
        None,
        None,
        Some(&android_path),
        None,
        None,
        None,
        backend_artifacts.clone(),
        empty_summary(),
        "sha256:witnesses".to_string(),
    );

    assert_eq!(manifest.backend_artifacts, backend_artifacts);
    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions for android output");
    assert_eq!(native.swift, None);
    assert_eq!(
        native.kotlin.as_deref(),
        Some(ANDROID_COMPOSE_EMITTER_API_VERSION)
    );
}

#[test]
fn legacy_kotlin_backend_id_still_projects_native_api_versions() {
    let out = temp_dir("legacy-kotlin-backend-artifacts");
    let kotlin_path = out.join("tokens.kt");
    fs::write(&kotlin_path, "// legacy kotlin").expect("write legacy kotlin source");

    let legacy_artifacts = vec![backend_artifact(
        "kotlin",
        BackendArtifactDescriptorKind::PrimaryTokenOutput,
        &kotlin_path,
        Some(ANDROID_COMPOSE_EMITTER_API_VERSION),
    )];

    let native = legacy_native_api_versions_from_backend_artifacts(&legacy_artifacts)
        .expect("expected nativeApiVersions from legacy kotlin backend id");
    assert_eq!(native.swift, None);
    assert_eq!(
        native.kotlin.as_deref(),
        Some(ANDROID_COMPOSE_EMITTER_API_VERSION)
    );
}

#[test]
fn legacy_swift_backend_id_still_projects_native_api_versions() {
    let out = temp_dir("legacy-swift-backend-artifacts");
    let swift_path = out.join("tokens.swift");
    fs::write(&swift_path, "// legacy swift").expect("write legacy swift source");

    let legacy_artifacts = vec![backend_artifact(
        "swift",
        BackendArtifactDescriptorKind::PrimaryTokenOutput,
        &swift_path,
        Some(SWIFT_EMITTER_API_VERSION),
    )];

    let native = legacy_native_api_versions_from_backend_artifacts(&legacy_artifacts)
        .expect("expected nativeApiVersions from legacy swift backend id");
    assert_eq!(native.swift.as_deref(), Some(SWIFT_EMITTER_API_VERSION));
    assert_eq!(native.kotlin, None);
}

#[test]
fn compose_manifest_preserves_backend_artifacts_and_native_api_versions() {
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
    let out = temp_dir("compose-native-swift");
    let swift_path = out.join("tokens.swift");
    fs::write(&swift_path, "// swift").expect("write swift");
    let backend_artifacts = vec![backend_artifact(
        "swift-tokens",
        BackendArtifactDescriptorKind::PrimaryTokenOutput,
        &swift_path,
        Some(SWIFT_EMITTER_API_VERSION),
    )];

    let manifest = build_compose_manifest(
        &[],
        &out,
        &BTreeMap::new(),
        &policy,
        ConflictMode::Semantic,
        backend_artifacts.clone(),
        native_versions,
        "sha256:w".to_string(),
        &witnesses,
    )
    .expect("compose manifest");

    assert_eq!(manifest.backend_artifacts, backend_artifacts);
    let native = manifest
        .native_api_versions
        .expect("expected nativeApiVersions on compose manifest");
    assert_eq!(native.swift.as_deref(), Some(SWIFT_EMITTER_API_VERSION));
    assert_eq!(native.kotlin, None);
}
