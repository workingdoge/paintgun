use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::emit::{
    emit_kotlin_module_scaffold, emit_store_kotlin, emit_store_swift, emit_swift_package_scaffold,
    KOTLIN_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION,
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

fn example_store() -> (PathBuf, paintgun::resolver::TokenStore) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");
    (resolver_path, store)
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
fn kotlin_module_scaffold_is_emitted() {
    let (_resolver_path, store) = example_store();
    let policy = Policy::default();
    let kotlin_source = emit_store_kotlin(&store, &policy);
    let out = temp_dir("kotlin-scaffold");

    emit_kotlin_module_scaffold(&out, &kotlin_source).expect("emit kotlin scaffold");

    let settings = out.join("kotlin/settings.gradle.kts");
    let build = out.join("kotlin/build.gradle.kts");
    let source = out.join("kotlin/src/main/kotlin/paintgun/PaintgunTokens.kt");
    let test = out.join("kotlin/src/test/kotlin/paintgun/PaintgunTokensSmokeTest.kt");
    assert_exists(&settings);
    assert_exists(&build);
    assert_exists(&source);
    assert_exists(&test);

    let build_content = fs::read_to_string(build).expect("read build.gradle.kts");
    assert!(
        build_content.contains("kotlin(\"jvm\")"),
        "kotlin module should declare jvm plugin"
    );
    let source_content = fs::read_to_string(source).expect("read kotlin source");
    assert!(
        source_content.contains("object PaintgunTokens"),
        "kotlin source should include PaintgunTokens object"
    );
    assert!(
        source_content.contains(".toDouble()"),
        "kotlin source should emit numeric values as Double expressions"
    );
    assert!(
        source_content.contains("PAINTGUN_EMITTER_API_VERSION"),
        "kotlin source should include native API version marker"
    );
    assert!(
        source_content.contains(KOTLIN_EMITTER_API_VERSION),
        "kotlin source should carry expected API version"
    );
}
