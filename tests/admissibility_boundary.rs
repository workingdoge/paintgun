use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn analysis_module_delegates_to_premath_admissibility() {
    let src = read_from_manifest("src/analysis.rs");
    assert!(
        src.contains("premath_admissibility::kan_diag")
            && src.contains("premath_admissibility::stability_failures")
            && src.contains("premath_admissibility::locality_failures")
            && src.contains("premath_admissibility::bc_violations"),
        "src/analysis.rs should delegate admissibility kernels to premath-admissibility"
    );
}

#[test]
fn premath_admissibility_module_hosts_poset_kernels() {
    let src = read_from_manifest("../premath/crates/premath-admissibility/src/lib.rs");
    for symbol in [
        "pub fn kan_diag",
        "pub fn bc_violations",
        "pub fn stability_failures",
        "pub fn locality_failures",
        "pub fn orthogonality_overlaps",
    ] {
        assert!(
            src.contains(symbol),
            "premath-admissibility should host {symbol}"
        );
    }
}
