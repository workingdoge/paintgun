use std::path::PathBuf;

use serde_json::Value;

use paintgun::cert::{analyze_composability, build_assignments, build_explicit_index};
use paintgun::contexts::partial_inputs;
use paintgun::gate::{evaluate_from_analysis, GateResult};
use paintgun::resolver::{build_token_store, read_json_file, ResolverDoc};

fn resolver_from_fixture(path: &str) -> (ResolverDoc, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join(path);
    let input_json: Value = read_json_file(&fixture).expect("fixture input json");
    let resolver: ResolverDoc = serde_json::from_value(
        input_json
            .get("resolver")
            .cloned()
            .expect("fixture resolver field"),
    )
    .expect("resolver doc");
    let resolver_path = fixture
        .parent()
        .expect("fixture parent")
        .join("fixture.resolver.json");
    (resolver, resolver_path)
}

#[test]
fn admissibility_runtime_reports_rejected_when_failures_exist() {
    let (resolver, resolver_path) = resolver_from_fixture(
        "tests/conformance/fixtures/gate/golden/gate_analysis_conflict_bc/input.json",
    );
    let store = build_token_store(&resolver, &resolver_path).expect("token store");
    let analysis = analyze_composability(&resolver, &store, &resolver_path).expect("analysis");
    let explicit = build_explicit_index(&resolver, &store, &resolver_path).expect("explicit");
    let assignments = build_assignments(&store, &explicit);
    let contexts = partial_inputs(&store.axes);
    let admissibility = evaluate_from_analysis(&analysis, &assignments, &store.axes, &contexts);

    assert_eq!(
        admissibility.result,
        GateResult::Rejected,
        "expected rejected admissibility result"
    );
    assert!(
        admissibility
            .failures
            .iter()
            .any(|f| f.class_name == "stability_failure" && f.law_ref == "GATE-3.1"),
        "expected stability failure"
    );
    admissibility.validate().expect("admissibility validation");
}

#[test]
fn admissibility_runtime_reports_accepted_when_no_failures_exist() {
    let (resolver, resolver_path) = resolver_from_fixture(
        "tests/conformance/fixtures/gate/golden/gate_analysis_no_failures/input.json",
    );
    let store = build_token_store(&resolver, &resolver_path).expect("token store");
    let analysis = analyze_composability(&resolver, &store, &resolver_path).expect("analysis");
    let explicit = build_explicit_index(&resolver, &store, &resolver_path).expect("explicit");
    let assignments = build_assignments(&store, &explicit);
    let contexts = partial_inputs(&store.axes);
    let admissibility = evaluate_from_analysis(&analysis, &assignments, &store.axes, &contexts);

    assert_eq!(
        admissibility.result,
        GateResult::Accepted,
        "expected accepted admissibility result"
    );
    assert!(
        admissibility.failures.is_empty(),
        "accepted admissibility result must have empty failures"
    );
    admissibility.validate().expect("admissibility validation");
}
