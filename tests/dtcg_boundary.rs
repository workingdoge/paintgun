use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn dtcg_module_is_a_compat_reexport() {
    let src = read_from_manifest("src/dtcg.rs");
    assert!(
        src.contains("pub use tbp_dtcg::*;"),
        "src/dtcg.rs should re-export the standalone tbp-dtcg crate"
    );
}

#[test]
fn tbp_dtcg_crate_hosts_dtcg_domain_types() {
    let src = read_from_manifest("crates/tbp-dtcg/src/lib.rs");
    for symbol in [
        "pub enum DtcgType",
        "pub struct TypedValue",
        "pub enum DtcgValue",
        "pub enum JValue",
    ] {
        assert!(src.contains(symbol), "tbp-dtcg should host {symbol}");
    }
}
