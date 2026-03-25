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
        cert_src.contains("pub type CtcSummary = premath_composability::AnalysisSummary;"),
        "src/cert.rs should alias composability model from premath-composability"
    );
    assert!(
        cert_src.contains("premath_composability::analyze_assignments("),
        "src/cert.rs should delegate composability witness assembly to premath-composability"
    );
    for alias_def in [
        "pub type CtcSummary = premath_composability::AnalysisSummary;",
        "pub type CtcWitnesses = premath_composability::AnalysisWitnesses<TokenProvenance>;",
        "pub type CtcGapWitness = premath_composability::GapWitness;",
        "pub type CtcConflictWitness = premath_composability::ConflictWitness;",
    ] {
        assert!(
            cert_src.contains(alias_def),
            "src/cert.rs should expose {alias_def}"
        );
    }
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
fn premath_composability_hosts_generic_analysis_model() {
    let model_src = read_from_manifest("../premath/crates/premath-composability/src/lib.rs");
    for symbol in [
        "pub enum ConflictMode",
        "pub struct AnalysisSummary",
        "pub struct AnalysisWitnesses",
        "pub struct GapWitness",
        "pub struct ConflictWitness",
        "pub struct InheritedWitness",
        "pub struct BcWitness",
        "pub struct OverlapWitness",
        "pub struct Analysis",
    ] {
        assert!(
            model_src.contains(symbol),
            "premath-composability should host {symbol}"
        );
    }
    for legacy_symbol in [
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
            !model_src.contains(legacy_symbol),
            "premath-composability should not expose legacy symbol {legacy_symbol}"
        );
    }
}
