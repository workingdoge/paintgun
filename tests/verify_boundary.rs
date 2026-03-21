use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn verify_module_delegates_profile_binding_logic_to_submodule() {
    let src = read_from_manifest("src/verify.rs");
    assert!(
        src.contains("mod profile_binding;"),
        "src/verify.rs should declare profile_binding submodule"
    );
    assert!(
        src.contains("use profile_binding::{check_expected_profile_anchors, check_manifest_profile_binding};"),
        "src/verify.rs should import profile-binding checks from submodule"
    );
    assert!(
        src.contains("pub use profile_binding::validate_manifest_profile_binding;"),
        "src/verify.rs should re-export profile-binding validator"
    );
    assert!(
        !src.contains("fn check_manifest_profile_binding("),
        "src/verify.rs should not define manifest profile-binding checks inline"
    );
    assert!(
        !src.contains("fn check_expected_profile_anchors("),
        "src/verify.rs should not define expected-anchor checks inline"
    );
}

#[test]
fn verify_profile_binding_submodule_hosts_spec_normative_checks() {
    let src = read_from_manifest("src/verify/profile_binding.rs");
    for symbol in [
        "fn parse_anchor_root_bytes",
        "fn anchors_from_manifest_profile",
        "pub(crate) fn check_manifest_profile_binding",
        "pub fn validate_manifest_profile_binding",
        "pub(crate) fn check_expected_profile_anchors",
    ] {
        assert!(
            src.contains(symbol),
            "src/verify/profile_binding.rs should host {symbol}"
        );
    }
}
