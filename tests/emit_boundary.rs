use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn emit_module_delegates_native_logic_to_paintgun_emit() {
    let src = read_from_manifest("src/emit.rs");
    assert!(
        src.contains("emit_store_swift_with_lookup("),
        "src/emit.rs should delegate Swift emission to paintgun-emit kernel"
    );
    assert!(
        src.contains("emit_store_kotlin_with_lookup("),
        "src/emit.rs should delegate Kotlin emission to paintgun-emit kernel"
    );
}

#[test]
fn paintgun_emit_crate_hosts_emission_kernel_types() {
    let src = read_from_manifest("crates/paintgun-emit/src/lib.rs");
    for symbol in [
        "pub trait Emitter",
        "pub struct CssEmitter",
        "pub struct Contract",
        "pub struct LayerDef",
        "pub struct EmissionToken",
        "pub fn compile_component_css_with_layers_lookup",
        "pub fn emit_store_swift_with_lookup",
        "pub fn emit_store_kotlin_with_lookup",
    ] {
        assert!(src.contains(symbol), "paintgun-emit should host {symbol}");
    }
}

#[test]
fn backend_module_hosts_target_registry_contract() {
    let src = read_from_manifest("src/backend.rs");
    for symbol in [
        "pub trait TargetBackend",
        "pub struct BackendRequest",
        "pub struct BackendEmission",
        "pub fn resolve_target_backend",
        "pub fn supported_target_names",
    ] {
        assert!(src.contains(symbol), "src/backend.rs should host {symbol}");
    }
    assert!(
        src.contains("emit_css_token_stylesheet_for_build("),
        "src/backend.rs should delegate CSS token emission to src/web_css.rs"
    );
    assert!(
        src.contains("emit_component_package_stylesheet("),
        "src/backend.rs should delegate component package CSS to src/web_css.rs"
    );
}

#[test]
fn web_css_module_hosts_css_split_adapter() {
    let src = read_from_manifest("src/web_css.rs");
    for symbol in [
        "pub fn css_custom_property_name",
        "pub fn emit_css_token_stylesheet_for_build",
        "pub fn emit_css_token_stylesheet_for_compose",
        "pub fn emit_component_package_stylesheet",
        "pub fn emit_component_package_types",
        "pub fn assemble_css_compat_stylesheet",
    ] {
        assert!(src.contains(symbol), "src/web_css.rs should host {symbol}");
    }
}
