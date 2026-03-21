use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn resolver_io_module_hosts_fs_adapter_and_callback_bridge() {
    let src = read_from_manifest("src/resolver_io.rs");
    for symbol in [
        "pub trait ResolverIo",
        "pub struct FsResolverIo",
        "impl ResolverIo for FsResolverIo",
        "pub fn load_source_with_io",
        "pub fn flatten_with_io",
        "pub fn axes_relevant_to_tokens_with_io",
    ] {
        assert!(
            src.contains(symbol),
            "src/resolver_io.rs should host {symbol}"
        );
    }
}

#[test]
fn resolver_module_uses_resolver_io_adapter() {
    let src = read_from_manifest("src/resolver.rs");
    assert!(
        src.contains("use crate::resolver_io::{"),
        "src/resolver.rs should import the resolver_io adapter module"
    );
    assert!(
        src.contains("load_source_with_io(&FsResolverIo"),
        "src/resolver.rs should use resolver_io for load_source"
    );
    assert!(
        src.contains("flatten_with_io(&FsResolverIo"),
        "src/resolver.rs should use resolver_io for flatten"
    );
    assert!(
        src.contains("axes_relevant_to_tokens_with_io(&FsResolverIo"),
        "src/resolver.rs should use resolver_io for axis relevance planning"
    );
}
