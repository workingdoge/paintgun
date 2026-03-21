use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn resolver_module_delegates_tree_primitives_to_kernel() {
    let src = read_from_manifest("src/resolver.rs");
    assert!(
        src.contains("use tbp_resolver_kernel::{")
            && src.contains("FlattenError")
            && src.contains("use crate::resolver_io::{")
            && src.contains("FsResolverIo"),
        "src/resolver.rs should import kernel errors and resolver-io adapter seam"
    );
    assert!(
        !src.contains("fn deep_merge("),
        "src/resolver.rs should not define deep_merge locally"
    );
    assert!(
        !src.contains("fn parse_json_pointer("),
        "src/resolver.rs should not define parse_json_pointer locally"
    );
    assert!(
        !src.contains("fn resolve_extends_inner("),
        "src/resolver.rs should not define extends recursion locally"
    );
    assert!(
        !src.contains("fn resolve_token("),
        "src/resolver.rs should not define alias recursion locally"
    );
    assert!(
        src.contains("tbp_resolver_kernel::resolve_extends(tree)"),
        "src/resolver.rs should delegate resolve_extends to kernel"
    );
    assert!(
        src.contains("load_source_with_io(&FsResolverIo"),
        "src/resolver.rs should delegate load_source through resolver-io adapter"
    );
    assert!(
        src.contains("flatten_with_io(&FsResolverIo"),
        "src/resolver.rs should delegate flatten through resolver-io adapter"
    );
    assert!(
        src.contains("axes_relevant_to_tokens_with_io(&FsResolverIo"),
        "src/resolver.rs should delegate axis relevance planning through resolver-io adapter"
    );
    assert!(
        src.contains("tbp_resolver_kernel::resolve_aliases(tokens)"),
        "src/resolver.rs should delegate resolve_aliases to kernel"
    );
    assert!(
        src.contains("tbp_resolver_kernel::materialize(tree, source)"),
        "src/resolver.rs should delegate materialize to kernel"
    );
    assert!(
        src.contains("tbp_resolver_kernel::collect_explicit_token_paths(tree)"),
        "src/resolver.rs should delegate explicit-token path collection to kernel"
    );
    assert!(
        src.contains("tbp_resolver_kernel::collect_explicit_token_defs(tree)"),
        "src/resolver.rs should delegate explicit-token definition collection to kernel"
    );
    assert!(
        src.contains(
            "tbp_resolver_kernel::canonicalize_token(token).map_err(map_canonicalize_error)"
        ),
        "src/resolver.rs should delegate canonicalization to kernel with adapter error mapping"
    );
    assert!(
        !src.contains("fn canonicalize_color("),
        "src/resolver.rs should not define color canonicalization locally"
    );
    assert!(
        !src.contains("fn parse_type("),
        "src/resolver.rs should not define parse_type locally"
    );
    assert!(
        !src.contains("fn load_source_with_refs("),
        "src/resolver.rs should not define source-ref recursion locally"
    );
    assert!(
        !src.contains("fn load_sources_with_refs("),
        "src/resolver.rs should not define multi-source recursion locally"
    );
    assert!(
        !src.contains("fn resolve_order_entry("),
        "src/resolver.rs should not define resolution-order dispatch locally"
    );
    assert!(
        !src.contains("fn resolve_existing_under_safe("),
        "src/resolver.rs should not define path-safety callback glue locally"
    );
    assert!(
        !src.contains("fn read_json_file_for_kernel("),
        "src/resolver.rs should not define kernel JSON callback glue locally"
    );
}

#[test]
fn resolver_kernel_crate_hosts_tree_primitives() {
    let src = read_from_manifest("crates/tbp-resolver-kernel/src/lib.rs");
    for symbol in [
        "pub fn deep_merge",
        "pub fn parse_json_pointer",
        "pub enum LoadFileError",
        "pub enum FlattenError",
        "pub fn load_source_with_refs",
        "pub fn load_source",
        "pub fn load_sources",
        "pub fn flatten",
        "pub fn axes_relevant_to_tokens",
        "pub fn lookup_json_pointer",
        "pub fn lookup_extends_target",
        "pub enum ExtendsError",
        "pub fn resolve_extends",
        "pub enum AliasError",
        "pub fn resolve_aliases",
        "pub fn materialize",
        "pub fn collect_explicit_token_paths",
        "pub fn collect_explicit_token_defs",
        "pub enum CanonicalizeError",
        "pub fn canonicalize_token",
    ] {
        assert!(
            src.contains(symbol),
            "tbp-resolver-kernel should host {symbol}"
        );
    }
}
