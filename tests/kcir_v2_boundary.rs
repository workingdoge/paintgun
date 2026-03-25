use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn kcir_v2_module_keeps_kernel_calls_in_compat() {
    let kcir_v2_src = read_from_manifest("../premath/crates/premath-kcir/src/kcir_v2.rs");
    assert!(
        !kcir_v2_src.contains("kcir_kernel"),
        "premath-kcir/src/kcir_v2.rs should not reference kcir_kernel directly"
    );
    assert!(
        !kcir_v2_src.contains("kcir::"),
        "premath-kcir/src/kcir_v2.rs should not call kernel items directly; route through compat"
    );
}

#[test]
fn kcir_v2_compat_module_hosts_kernel_bridge() {
    let compat_src = read_from_manifest("../premath/crates/premath-kcir/src/kcir_v2/compat.rs");
    assert!(
        compat_src.contains("use premath_kcir_kernel as kernel;"),
        "compat module should bridge through the premath-kcir-kernel crate"
    );
}
