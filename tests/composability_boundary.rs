use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn cert_module_reexports_composability_model() {
    let cert_src = read_from_manifest("src/cert.rs");
    assert!(
        cert_src.contains("pub use premath_composability::{"),
        "src/cert.rs should re-export composability model from premath-composability"
    );
    assert!(
        cert_src.contains("premath_composability::analyze_assignments("),
        "src/cert.rs should delegate composability witness assembly to premath-composability"
    );
    for local_def in [
        "pub struct CtcWitnesses",
        "pub struct CtcGapWitness",
        "pub struct CtcConflictWitness",
        "pub struct CtcSummary",
    ] {
        assert!(
            !cert_src.contains(local_def),
            "src/cert.rs should not define {local_def} locally"
        );
    }
}

#[test]
fn premath_composability_hosts_ctc_model() {
    let model_src = read_from_manifest("crates/premath-composability/src/lib.rs");
    for symbol in [
        "pub enum ConflictMode",
        "pub struct CtcSummary",
        "pub struct CtcWitnesses",
        "pub struct CtcGapWitness",
        "pub struct CtcConflictWitness",
        "pub struct CtcInheritedWitness",
        "pub struct CtcBcWitness",
        "pub struct CtcOverlapWitness",
        "pub struct CtcAnalysis",
    ] {
        assert!(
            model_src.contains(symbol),
            "premath-composability should host {symbol}"
        );
    }
}
