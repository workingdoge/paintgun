use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn resolver_runtime_module_hosts_token_store_orchestration() {
    let src = read_from_manifest("src/resolver_runtime.rs");
    for symbol in [
        "fn map_input_selection_error",
        "pub fn build_token_store_for_inputs",
        "pub fn build_token_store",
    ] {
        assert!(
            src.contains(symbol),
            "src/resolver_runtime.rs should host {symbol}"
        );
    }
    assert!(
        src.contains("use crate::resolver_io::{flatten_with_io, FsResolverIo};"),
        "src/resolver_runtime.rs should use resolver_io seam directly"
    );
    assert!(
        src.contains("tbp_resolver_kernel::resolve_extends(&tree)"),
        "src/resolver_runtime.rs should use kernel resolution directly"
    );
    assert!(
        !src.contains("use crate::resolver::{"),
        "src/resolver_runtime.rs should not depend on resolver facade helpers"
    );
}

#[test]
fn resolver_module_delegates_token_store_build_to_runtime() {
    let src = read_from_manifest("src/resolver.rs");
    assert!(
        src.contains("crate::resolver_runtime::build_token_store_for_inputs("),
        "src/resolver.rs should delegate input-planned token-store build to resolver_runtime"
    );
    assert!(
        src.contains("crate::resolver_runtime::build_token_store("),
        "src/resolver.rs should delegate default token-store build to resolver_runtime"
    );
}
