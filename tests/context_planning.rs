use std::collections::{BTreeMap, BTreeSet};

use paintgun::contexts::{plan_inputs, ContextMode};

fn axes_three_by_two() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        (
            "density".to_string(),
            vec!["compact".to_string(), "comfortable".to_string()],
        ),
        (
            "state".to_string(),
            vec!["default".to_string(), "hover".to_string()],
        ),
        (
            "theme".to_string(),
            vec!["dark".to_string(), "light".to_string()],
        ),
    ])
}

#[test]
fn context_modes_have_expected_cardinality() {
    let axes = axes_three_by_two();
    let full = plan_inputs(ContextMode::FullOnly, &axes, None);
    let partial = plan_inputs(ContextMode::Partial, &axes, None);
    let from_contracts = plan_inputs(ContextMode::FromContracts, &axes, None);

    assert_eq!(
        full.len(),
        8,
        "3 axes x 2 values should have 2^3 full contexts"
    );
    assert_eq!(
        partial.len(),
        27,
        "partial lattice cardinality should be (1+2)^3"
    );
    assert_eq!(
        from_contracts.len(),
        19,
        "layered contexts should include base + singles + pairwise"
    );
}

#[test]
fn from_contracts_can_scope_to_relevant_axes() {
    let axes = axes_three_by_two();
    let relevant = BTreeSet::from(["theme".to_string(), "density".to_string()]);
    let planned = plan_inputs(ContextMode::FromContracts, &axes, Some(&relevant));

    // base + singles (2+2) + pairwise (2x2) = 9
    assert_eq!(planned.len(), 9);
    assert!(
        planned
            .iter()
            .all(|ctx| !ctx.contains_key("state") || ctx.len() <= 1),
        "state axis should not appear in contract-scoped pairwise contexts"
    );
}
