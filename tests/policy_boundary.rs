use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn policy_module_is_a_compat_reexport() {
    let src = read_from_manifest("src/policy.rs");
    assert!(
        src.contains("pub use paintgun_policy::*;"),
        "src/policy.rs should re-export the standalone paintgun-policy crate"
    );
}

#[test]
fn paintgun_policy_crate_hosts_policy_domain_types() {
    let src = read_from_manifest("crates/paintgun-policy/src/lib.rs");
    for symbol in [
        "pub struct Policy",
        "pub struct KcirPolicy",
        "pub enum CssColorPolicy",
        "pub fn normalize_value",
        "pub fn policy_digest",
    ] {
        assert!(src.contains(symbol), "paintgun-policy should host {symbol}");
    }
}
