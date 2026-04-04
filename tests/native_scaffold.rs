use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::emit::{
    emit_kotlin_module_scaffold, emit_store_kotlin, emit_store_swift, emit_swift_package_scaffold,
    ANDROID_COMPOSE_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION,
};
use paintgun::policy::Policy;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn example_store_from(relative: &str) -> (PathBuf, paintgun::resolver::TokenStore) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join(relative);
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    (resolver_path, store)
}

fn example_store() -> (PathBuf, paintgun::resolver::TokenStore) {
    example_store_from("examples/charter-steel/charter-steel.resolver.json")
}

fn assert_exists(path: &Path) {
    assert!(path.exists(), "expected file to exist: {}", path.display());
}

#[test]
fn swift_package_scaffold_is_emitted() {
    let (_resolver_path, store) = example_store();
    let policy = Policy::default();
    let swift_source = emit_store_swift(&store, &policy);
    let out = temp_dir("swift-scaffold");

    emit_swift_package_scaffold(&out, &swift_source).expect("emit swift scaffold");

    let package_swift = out.join("swift/Package.swift");
    let module_swift = out.join("swift/Sources/PaintgunTokens/PaintgunTokens.swift");
    let test_swift = out.join("swift/Tests/PaintgunTokensTests/PaintgunTokensTests.swift");
    assert_exists(&package_swift);
    assert_exists(&module_swift);
    assert_exists(&test_swift);

    let package_content = fs::read_to_string(package_swift).expect("read Package.swift");
    assert!(
        package_content.contains("name: \"PaintgunTokens\""),
        "swift package manifest should define module name"
    );
    let module_content = fs::read_to_string(module_swift).expect("read module swift");
    assert!(
        module_content.contains("public struct PaintgunTokens"),
        "swift module should include PaintgunTokens struct"
    );
    assert!(
        module_content.contains("public enum PaintgunEmitterAPI"),
        "swift module should include native API version marker"
    );
    assert!(
        module_content.contains(SWIFT_EMITTER_API_VERSION),
        "swift module should carry expected API version"
    );
}

#[test]
fn android_compose_module_scaffold_is_emitted() {
    let (_resolver_path, store) = example_store();
    let policy = Policy::default();
    let kotlin_source = emit_store_kotlin(&store, &policy);
    let out = temp_dir("android-scaffold");

    emit_kotlin_module_scaffold(&out, &kotlin_source).expect("emit android scaffold");

    let settings = out.join("android/settings.gradle.kts");
    let build = out.join("android/build.gradle.kts");
    let source = out.join("android/src/main/kotlin/paintgun/PaintgunTokens.kt");
    let test = out.join("android/src/test/kotlin/paintgun/PaintgunTokensSmokeTest.kt");
    assert_exists(&settings);
    assert_exists(&build);
    assert_exists(&source);
    assert_exists(&test);

    let settings_content = fs::read_to_string(settings).expect("read settings.gradle.kts");
    assert!(
        settings_content.contains("paintgun-android-compose-tokens"),
        "android settings should use the platform-facing module name"
    );
    let build_content = fs::read_to_string(build).expect("read build.gradle.kts");
    assert!(
        build_content.contains("kotlin(\"jvm\")"),
        "android module should declare jvm plugin"
    );
    let source_content = fs::read_to_string(source).expect("read kotlin source");
    assert!(
        source_content.contains("object PaintgunTokens"),
        "android source should include PaintgunTokens object"
    );
    assert!(
        source_content.contains(".toDouble()"),
        "android source should emit numeric values as Double expressions"
    );
    assert!(
        source_content.contains("PAINTGUN_EMITTER_API_VERSION"),
        "android source should include native API version marker"
    );
    assert!(
        source_content.contains(ANDROID_COMPOSE_EMITTER_API_VERSION),
        "android source should carry expected API version"
    );
}

#[test]
fn swift_scaffold_preserves_alpha_color_paths() {
    let (_resolver_path, store) =
        example_store_from("examples/native-color-edge/native-color-edge.resolver.json");
    let policy = Policy::default();
    let swift_source = emit_store_swift(&store, &policy);
    let out = temp_dir("swift-alpha");

    emit_swift_package_scaffold(&out, &swift_source).expect("emit swift scaffold");

    let module_swift = out.join("swift/Sources/PaintgunTokens/PaintgunTokens.swift");
    let module_content = fs::read_to_string(module_swift).expect("read module swift");
    assert!(
        module_content.contains("paintgunColor(red: 0.1, green: 0.2, blue: 0.3, opacity: 0.5)"),
        "swift scaffold should preserve numeric-component alpha colors"
    );
    assert!(
        module_content.contains("paintgunColor(red: 0.2, green: 0.4, blue: 0.6, opacity: 0.25)"),
        "swift scaffold should preserve hex-backed alpha colors"
    );
}

#[test]
fn android_scaffold_emits_argb_for_alpha_color_paths() {
    let (_resolver_path, store) =
        example_store_from("examples/native-color-edge/native-color-edge.resolver.json");
    let policy = Policy::default();
    let kotlin_source = emit_store_kotlin(&store, &policy);
    let out = temp_dir("android-alpha");

    emit_kotlin_module_scaffold(&out, &kotlin_source).expect("emit android scaffold");

    let source = out.join("android/src/main/kotlin/paintgun/PaintgunTokens.kt");
    let source_content = fs::read_to_string(source).expect("read kotlin source");
    assert!(
        source_content.contains("PaintgunColor(0x801A334Du)"),
        "android scaffold should encode numeric-component alpha colors as ARGB UInts"
    );
    assert!(
        source_content.contains("PaintgunColor(0x40336699u)"),
        "android scaffold should encode hex-backed alpha colors as ARGB UInts"
    );
}
