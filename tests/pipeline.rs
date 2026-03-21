use std::path::PathBuf;

use serde_json::Value;

use tbp::cert::ConflictMode;
use tbp::contexts::ContextMode;
use tbp::gate::GateResult;
use tbp::pipeline::{run_full_profile_pipeline, FullProfilePipelineRequest};
use tbp::policy::Policy;
use tbp::resolver::{build_token_store, read_json_file, ResolverDoc};

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
fn full_profile_pipeline_is_deterministic_on_admissible_fixture() {
    let (resolver, resolver_path) = resolver_from_fixture(
        "tests/conformance/fixtures/gate/golden/gate_analysis_no_failures/input.json",
    );
    let store = build_token_store(&resolver, &resolver_path).expect("token store");
    let policy = Policy::default();

    let run1 = run_full_profile_pipeline(FullProfilePipelineRequest {
        doc: &resolver,
        store: &store,
        resolver_path: &resolver_path,
        conflict_mode: ConflictMode::Semantic,
        policy: &policy,
        context_mode: ContextMode::FullOnly,
        contract_tokens: None,
    })
    .expect("run pipeline");

    let run2 = run_full_profile_pipeline(FullProfilePipelineRequest {
        doc: &resolver,
        store: &store,
        resolver_path: &resolver_path,
        conflict_mode: ConflictMode::Semantic,
        policy: &policy,
        context_mode: ContextMode::FullOnly,
        contract_tokens: None,
    })
    .expect("run pipeline");

    assert!(
        !run1.resolve.explicit.is_empty(),
        "expected authored explicit index entries"
    );
    assert!(
        !run1.bidir.contexts.is_empty(),
        "expected planned checking contexts"
    );
    assert_eq!(
        run1.admissibility.witnesses.result,
        GateResult::Accepted,
        "fixture should be full-profile admissible"
    );
    run1.admissibility
        .witnesses
        .validate()
        .expect("admissibility witness validation");

    let w1 =
        serde_json::to_string(&run1.admissibility.witnesses).expect("serialize admissibility #1");
    let w2 =
        serde_json::to_string(&run2.admissibility.witnesses).expect("serialize admissibility #2");
    assert_eq!(w1, w2, "admissibility witness output must be deterministic");
}
