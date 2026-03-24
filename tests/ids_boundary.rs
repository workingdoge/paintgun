use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn ids_module_is_a_compat_reexport() {
    let src = read_from_manifest("src/ids.rs");
    assert!(
        src.contains("pub use paintgun_ids::*;"),
        "src/ids.rs should re-export the standalone paintgun-ids crate"
    );
}

#[test]
fn paintgun_ids_crate_hosts_typed_wrappers() {
    let src = read_from_manifest("crates/paintgun-ids/src/lib.rs");
    for symbol in [
        "define_id!(ContextId);",
        "define_id!(TokenPathId);",
        "define_id!(WitnessId);",
        "define_id!(RefId);",
        "define_id!(PackId);",
    ] {
        assert!(src.contains(symbol), "paintgun-ids should host {symbol}");
    }
}
