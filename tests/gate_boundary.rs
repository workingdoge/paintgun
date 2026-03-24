use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn paintgun_gate_module_is_adapter_only() {
    let gate_src = read_from_manifest("src/gate.rs");
    assert!(
        gate_src.contains("evaluate_admissibility(AdmissibilityInput"),
        "src/gate.rs should delegate to premath_gate::evaluate_admissibility"
    );
    for law in ["GATE-3.1", "GATE-3.2", "GATE-3.3", "GATE-3.4", "GATE-3.5"] {
        assert!(
            !gate_src.contains(law),
            "src/gate.rs should not host law-ref mapping ({law})"
        );
    }
}

#[test]
fn premath_gate_module_hosts_law_mapping() {
    let gate_core_src = read_from_manifest("crates/premath-gate/src/lib.rs");
    for law in ["GATE-3.1", "GATE-3.2", "GATE-3.3", "GATE-3.4", "GATE-3.5"] {
        assert!(
            gate_core_src.contains(law),
            "premath-gate should host law-ref mapping ({law})"
        );
    }
}
