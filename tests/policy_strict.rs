use paintgun::policy::Policy;

#[test]
fn legacy_top_level_policy_fields_are_rejected() {
    let legacy_json = r#"
    {
      "normalize_duration_to_ms": true,
      "normalize_dimension_to_px": true,
      "rem_base_px": 16
    }
    "#;

    let err =
        serde_json::from_str::<Policy>(legacy_json).expect_err("legacy keys must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field"),
        "expected unknown field error, got: {msg}"
    );
}

#[test]
fn unknown_nested_policy_fields_are_rejected() {
    let bad_nested = r#"
    {
      "duration": { "prefer": "ms", "legacyFlag": true }
    }
    "#;

    let err = serde_json::from_str::<Policy>(bad_nested)
        .expect_err("unknown nested keys must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field"),
        "expected unknown field error, got: {msg}"
    );
}

#[test]
fn kcir_policy_fields_are_accepted_and_unknown_keys_rejected() {
    let ok = r#"
    {
      "kcir": {
        "schemeId": "hash",
        "paramsHash": "sha256:abc",
        "wireFormatId": "kcir.wire.legacy-fixed32.v1",
        "anchorRootCommitment": "sha256:deadbeef",
        "anchorTreeEpoch": 7
      }
    }
    "#;
    serde_json::from_str::<Policy>(ok).expect("kcir policy fields should be accepted");

    let bad = r#"
    {
      "kcir": {
        "schemeId": "hash",
        "unexpected": true
      }
    }
    "#;
    let err = serde_json::from_str::<Policy>(bad)
        .expect_err("unknown kcir policy fields must be rejected");
    assert!(
        err.to_string().contains("unknown field"),
        "expected unknown field error, got: {err}"
    );
}
