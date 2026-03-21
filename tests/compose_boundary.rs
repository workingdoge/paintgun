use std::fs;
use std::path::PathBuf;

fn read_from_manifest(relative: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(relative);
    fs::read_to_string(path).expect("boundary source file should be readable")
}

#[test]
fn compose_module_delegates_conflict_assembly() {
    let src = read_from_manifest("src/compose.rs");
    assert!(
        src.contains("assemble_conflicts("),
        "src/compose.rs should delegate conflict witness assembly to premath-compose"
    );
    assert!(
        src.contains("verify_pack_with_callbacks("),
        "src/compose.rs should route per-pack verification through premath-compose callbacks"
    );
    assert!(
        !src.contains("fn verify_compose_pack("),
        "src/compose.rs should not define per-pack verification kernel locally"
    );
    assert!(
        !src.contains("fn compose_witness_id("),
        "src/compose.rs should not define compose witness-id hashing locally"
    );
    for local_def in [
        "pub struct ComposeConflictCandidate",
        "pub struct ComposeInheritedRef",
        "pub struct ComposeConflictWitness",
        "pub struct ComposeWitnesses",
        "pub struct ComposePackEntry",
        "pub struct ComposeManifest",
        "pub struct ComposeSummary",
        "pub struct ComposeVerifyReport",
        "pub struct ComposeVerifyError",
    ] {
        assert!(
            !src.contains(local_def),
            "src/compose.rs should not define {local_def} locally"
        );
    }
}

#[test]
fn premath_compose_hosts_conflict_kernel() {
    let src = read_from_manifest("crates/premath-compose/src/lib.rs");
    for symbol in [
        "pub const COMPOSE_WITNESS_SCHEMA_VERSION",
        "pub struct ComposeInheritedRef",
        "pub struct ComposeCandidateSource",
        "pub struct ComposeConflictWitness",
        "pub struct ComposeWitnesses",
        "pub struct ComposePackEntry",
        "pub struct ComposeManifest",
        "pub struct ComposeSummary",
        "pub struct ComposeVerifyReport",
        "pub struct ComposeVerifyError",
        "pub mod verify_error_codes",
        "pub fn push_verify_error",
        "pub fn check_required_signed",
        "pub fn check_pack_identity_match",
        "pub fn verify_witnesses_payload",
        "pub fn check_manifest_entry_binding",
        "pub fn fold_pack_verify_outcome",
        "pub fn prefix_pack_diagnostics",
        "pub fn verify_pack_with_callbacks",
        "pub fn summarize_pack_paths",
        "pub fn render_compose_report_text",
        "pub fn build_compose_report_json_value",
        "pub struct ComposeCandidateInput",
        "pub struct ComposeConflictDraftCandidate",
        "pub struct ComposeConflictDraft",
        "pub fn assemble_conflicts",
    ] {
        assert!(src.contains(symbol), "premath-compose should host {symbol}");
    }
}
