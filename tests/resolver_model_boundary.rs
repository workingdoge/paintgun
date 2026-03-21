use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn resolver_module_reexports_model_types() {
    let src = read_from_manifest("src/resolver.rs");
    assert!(
        src.contains("pub use tbp_resolver_model::{"),
        "src/resolver.rs should re-export resolver domain model types"
    );
    assert!(
        src.contains("validate_input_selection"),
        "src/resolver.rs should import model-level input selection validation"
    );
    assert!(
        !src.contains("struct RawResolverDoc"),
        "src/resolver.rs should not host resolver document parse model directly"
    );
    assert!(
        !src.contains("fn axes_from_doc("),
        "src/resolver.rs should not define axis derivation locally"
    );
    assert!(
        !src.contains("fn validate_input_selection("),
        "src/resolver.rs should not define input selection validation locally"
    );
    assert!(
        !src.contains("fn dedup_inputs_for_axes("),
        "src/resolver.rs should not define input deduplication locally"
    );
}

#[test]
fn resolver_model_crate_hosts_spec_structures() {
    let src = read_from_manifest("crates/tbp-resolver-model/src/lib.rs");
    for symbol in [
        "pub struct ResolverDoc",
        "struct RawResolverDoc",
        "impl<'de> Deserialize<'de> for ResolverDoc",
        "pub struct ResolverSource",
        "pub struct TokenStore",
        "pub enum InputSelectionError",
        "pub fn axes_from_doc",
        "pub fn validate_input_selection",
        "pub fn dedup_inputs_for_axes",
        "pub fn context_key",
        "pub fn parse_context_key",
    ] {
        assert!(
            src.contains(symbol),
            "tbp-resolver-model should host {symbol}"
        );
    }
}
