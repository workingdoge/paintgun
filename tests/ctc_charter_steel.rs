use std::path::PathBuf;

use paintgun::cert::analyze_composability;
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};

#[test]
fn charter_steel_flags_bc_violation_for_surface_bg() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");

    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let has = analysis.witnesses.bc_violations.iter().any(|w| {
        w.token_path == "color.surface.bg"
            && ((w.axis_a == "theme"
                && w.value_a == "dark"
                && w.axis_b == "mode"
                && w.value_b == "wellbeing")
                || (w.axis_a == "mode"
                    && w.value_a == "wellbeing"
                    && w.axis_b == "theme"
                    && w.value_b == "dark"))
    });

    assert!(
        has,
        "expected BC violation witness for color.surface.bg at (dark, wellbeing)"
    );
}

#[test]
fn charter_steel_flags_kan_conflict_for_surface_bg_at_intersection() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resolver_path = root.join("examples/charter-steel/charter-steel.resolver.json");

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store(&doc, &resolver_path).expect("token store");

    let analysis = analyze_composability(&doc, &store, &resolver_path).expect("ctc analysis");

    let has = analysis.witnesses.conflicts.iter().any(|w| {
        w.token_path == "color.surface.bg"
            && (w.target == "mode:wellbeing,theme:dark" || w.target == "theme:dark,mode:wellbeing")
    });

    assert!(
        has,
        "expected Kan conflict witness for color.surface.bg at (dark, wellbeing)"
    );
}
