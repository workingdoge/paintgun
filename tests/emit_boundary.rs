use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn emit_module_delegates_kernel_logic_to_paintgun_emit() {
    let src = read_from_manifest("src/emit.rs");
    assert!(
        src.contains("compile_component_css_with_layers_lookup("),
        "src/emit.rs should delegate CSS layer compilation to paintgun-emit kernel"
    );
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
