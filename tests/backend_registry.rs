use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::backend::{
    resolve_target_backend, supported_target_names, BackendArtifactKind, BackendRequest,
    BackendScope, BackendSource, LegacyTargetSlot,
};
use paintgun::emit::{
    Contract, ANDROID_COMPOSE_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION,
    WEB_TOKENS_TS_API_VERSION,
};
use paintgun::policy::Policy;
use paintgun::resolver::{
    axes_from_doc, build_token_store_for_inputs, read_json_file, supporting_inputs_for_selection,
    ResolverDoc,
};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example_resolver() -> PathBuf {
    repo_root().join("examples/charter-steel/charter-steel.resolver.json")
}

fn example_contracts() -> PathBuf {
    repo_root().join("examples/charter-steel/component-contracts.json")
}

fn load_contracts(path: &Path) -> Vec<Contract> {
    let value: serde_json::Value = read_json_file(path).expect("contracts json");
    let obj = value
        .as_object()
        .expect("contracts fixture should be a JSON object");
    let mut contracts = Vec::new();
    for (name, entry) in obj {
        if name.starts_with('$') {
            continue;
        }
        contracts.push(serde_json::from_value(entry.clone()).expect("contract entry"));
    }
    contracts
}

fn example_doc() -> ResolverDoc {
    read_json_file(&example_resolver()).expect("resolver doc")
}

fn backend_inputs_for_test(
    doc: &ResolverDoc,
    backend: &dyn paintgun::backend::TargetBackend,
    axes: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<paintgun::resolver::Input> {
    let required = backend.required_inputs(axes);
    if required.is_empty() {
        paintgun::contexts::full_inputs(axes)
    } else {
        supporting_inputs_for_selection(doc, &required)
    }
}

#[test]
fn registry_exposes_builtin_backend_specs() {
    assert_eq!(
        supported_target_names(),
        vec![
            "android-compose-tokens",
            "css",
            "kotlin",
            "swift",
            "swift-tokens",
            "web-css-vars",
            "web-tokens-ts",
        ]
    );

    let css = resolve_target_backend("web-css-vars").expect("css backend");
    assert_eq!(css.spec().id, "web-css-vars");
    assert_eq!(css.spec().legacy_slot, Some(LegacyTargetSlot::Css));
    assert!(css.spec().capabilities.requires_contracts);
    assert_eq!(css.spec().capabilities.scope, BackendScope::SystemPackage);

    let css_alias = resolve_target_backend("css").expect("css alias");
    assert_eq!(css_alias.spec().id, "web-css-vars");

    let swift = resolve_target_backend("swift-tokens").expect("swift backend");
    assert_eq!(swift.spec().id, "swift-tokens");
    assert_eq!(swift.spec().legacy_slot, Some(LegacyTargetSlot::Swift));
    assert_eq!(swift.spec().api_version, Some(SWIFT_EMITTER_API_VERSION));
    assert!(swift.spec().capabilities.emits_package_scaffold);

    let swift_alias = resolve_target_backend("swift").expect("swift alias");
    assert_eq!(swift_alias.spec().id, "swift-tokens");

    let android = resolve_target_backend("android-compose-tokens").expect("android backend");
    assert_eq!(
        android.spec().legacy_slot,
        Some(LegacyTargetSlot::AndroidCompose)
    );
    assert_eq!(
        android.spec().api_version,
        Some(ANDROID_COMPOSE_EMITTER_API_VERSION)
    );
    assert!(android.spec().capabilities.emits_package_scaffold);

    let kotlin_alias = resolve_target_backend("kotlin").expect("kotlin alias backend");
    assert_eq!(kotlin_alias.spec().id, "android-compose-tokens");
    assert_eq!(
        kotlin_alias.spec().api_version,
        Some(ANDROID_COMPOSE_EMITTER_API_VERSION)
    );

    let web = resolve_target_backend("web-tokens-ts").expect("web backend");
    assert_eq!(web.spec().legacy_slot, None);
    assert_eq!(web.spec().api_version, Some(WEB_TOKENS_TS_API_VERSION));
    assert!(web.spec().capabilities.emits_package_scaffold);
    assert_eq!(web.spec().capabilities.scope, BackendScope::TokenBackend);
}

#[test]
fn css_backend_emits_typed_artifacts_for_build() {
    let backend = resolve_target_backend("web-css-vars").expect("css backend");
    let out = temp_dir("backend-css");
    let doc = example_doc();
    let axes = axes_from_doc(&doc);
    let inputs = backend_inputs_for_test(&doc, backend, &axes);
    let store =
        build_token_store_for_inputs(&doc, &example_resolver(), &inputs).expect("build store");
    let contracts = load_contracts(&example_contracts());

    let emission = backend
        .emit(&BackendRequest {
            source: BackendSource::Build { doc: &doc },
            store: &store,
            policy: &Policy::default(),
            contracts: Some(contracts.as_slice()),
            out_dir: &out,
        })
        .expect("emit css backend");

    let primary = emission.primary_output().expect("primary css output");
    assert_eq!(primary.kind, BackendArtifactKind::PrimaryTokenOutput);
    assert_eq!(primary.relative_path, PathBuf::from("tokens.css"));
    assert!(out.join(&primary.relative_path).is_file());

    let token_css = emission
        .artifact(BackendArtifactKind::TokenStylesheet)
        .expect("raw token stylesheet");
    assert_eq!(token_css.relative_path, PathBuf::from("tokens.vars.css"));
    assert!(out.join(&token_css.relative_path).is_file());

    let system_css = emission
        .artifact(BackendArtifactKind::SystemStylesheet)
        .expect("system stylesheet");
    assert_eq!(system_css.relative_path, PathBuf::from("components.css"));
    assert!(out.join(&system_css.relative_path).is_file());

    let dts = emission
        .artifact(BackendArtifactKind::TypeDeclarations)
        .expect("type declarations");
    assert_eq!(dts.relative_path, PathBuf::from("tokens.d.ts"));
    assert!(out.join(&dts.relative_path).is_file());

    let compatibility_css = fs::read_to_string(out.join(&primary.relative_path))
        .expect("read compatibility stylesheet");
    let token_vars_css =
        fs::read_to_string(out.join(&token_css.relative_path)).expect("read token stylesheet");
    let component_css =
        fs::read_to_string(out.join(&system_css.relative_path)).expect("read system stylesheet");
    assert!(
        compatibility_css.contains("--paintgun-"),
        "compatibility css should include raw token variables"
    );
    assert!(
        token_vars_css.contains("@layer tokens."),
        "raw token stylesheet should contain token layers"
    );
    assert!(
        component_css.contains("@layer components"),
        "system stylesheet should contain components layer"
    );
    assert!(
        component_css.contains("var(--paintgun-"),
        "system stylesheet should reference token custom properties"
    );
}

#[test]
fn native_backends_emit_primary_output_and_scaffold_artifacts() {
    let doc = example_doc();
    for (target, primary_path, expected_api, manifest_kind) in [
        (
            "swift-tokens",
            "tokens.swift",
            Some(SWIFT_EMITTER_API_VERSION),
            BackendArtifactKind::PackageManifest,
        ),
        (
            "android-compose-tokens",
            "tokens.kt",
            Some(ANDROID_COMPOSE_EMITTER_API_VERSION),
            BackendArtifactKind::PackageBuildScript,
        ),
    ] {
        let backend = resolve_target_backend(target).expect("native backend");
        let out = temp_dir(&format!("backend-{target}"));
        let axes = axes_from_doc(&doc);
        let inputs = backend_inputs_for_test(&doc, backend, &axes);
        let store =
            build_token_store_for_inputs(&doc, &example_resolver(), &inputs).expect("build store");

        let emission = backend
            .emit(&BackendRequest {
                source: BackendSource::Build { doc: &doc },
                store: &store,
                policy: &Policy::default(),
                contracts: None,
                out_dir: &out,
            })
            .expect("emit native backend");

        let primary = emission.primary_output().expect("primary native output");
        assert_eq!(primary.kind, BackendArtifactKind::PrimaryTokenOutput);
        assert_eq!(primary.relative_path, PathBuf::from(primary_path));
        assert_eq!(primary.api_version, expected_api);
        assert_eq!(emission.backend_id, backend.spec().id);
        assert!(out.join(&primary.relative_path).is_file());

        let scaffold = emission.artifact(manifest_kind).expect("scaffold artifact");
        assert!(out.join(&scaffold.relative_path).is_file());
        assert!(
            emission
                .artifact(BackendArtifactKind::PackageSource)
                .is_some(),
            "expected package source artifact for {target}"
        );
        assert!(
            emission
                .artifact(BackendArtifactKind::PackageTest)
                .is_some(),
            "expected package test artifact for {target}"
        );
    }
}

#[test]
fn web_tokens_backend_emits_typed_package_artifacts() {
    let backend = resolve_target_backend("web-tokens-ts").expect("web backend");
    let out = temp_dir("backend-web-tokens");
    let doc = example_doc();
    let axes = axes_from_doc(&doc);
    let inputs = backend_inputs_for_test(&doc, backend, &axes);
    let store =
        build_token_store_for_inputs(&doc, &example_resolver(), &inputs).expect("build store");

    let emission = backend
        .emit(&BackendRequest {
            source: BackendSource::Build { doc: &doc },
            store: &store,
            policy: &Policy::default(),
            contracts: None,
            out_dir: &out,
        })
        .expect("emit web token backend");

    let primary = emission.primary_output().expect("primary web output");
    assert_eq!(primary.kind, BackendArtifactKind::PrimaryTokenOutput);
    assert_eq!(primary.relative_path, PathBuf::from("tokens.ts"));
    assert_eq!(primary.api_version, Some(WEB_TOKENS_TS_API_VERSION));
    assert_eq!(emission.backend_id, "web-tokens-ts");
    assert!(out.join(&primary.relative_path).is_file());

    let package_manifest = emission
        .artifact(BackendArtifactKind::PackageManifest)
        .expect("package manifest");
    assert_eq!(
        package_manifest.relative_path,
        PathBuf::from("web/package.json")
    );
    assert!(out.join(&package_manifest.relative_path).is_file());

    let package_settings = emission
        .artifact(BackendArtifactKind::PackageSettings)
        .expect("package settings");
    assert_eq!(
        package_settings.relative_path,
        PathBuf::from("web/tsconfig.json")
    );
    assert!(out.join(&package_settings.relative_path).is_file());

    let package_source = emission
        .artifact(BackendArtifactKind::PackageSource)
        .expect("package source");
    assert_eq!(
        package_source.relative_path,
        PathBuf::from("web/src/index.ts")
    );
    assert!(out.join(&package_source.relative_path).is_file());

    let package_test = emission
        .artifact(BackendArtifactKind::PackageTest)
        .expect("package test");
    assert_eq!(
        package_test.relative_path,
        PathBuf::from("web/src/index.test.ts")
    );
    assert!(out.join(&package_test.relative_path).is_file());

    let primary_content =
        fs::read_to_string(out.join(&primary.relative_path)).expect("read primary web output");
    assert!(
        primary_content.contains("PAINTGUN_WEB_TOKENS_API_VERSION"),
        "web token source should include API version marker"
    );
    assert!(
        primary_content.contains("valuesByContext"),
        "web token source should export typed token values by context"
    );
    assert!(
        primary_content.contains("export type PaintTokenValue"),
        "web token source should export typed token aliases"
    );

    let package_test_content =
        fs::read_to_string(out.join(&package_test.relative_path)).expect("read package test");
    assert!(
        package_test_content.contains("contexts[0]?.context"),
        "web package test should use the first emitted context instead of assuming a base context"
    );
}
