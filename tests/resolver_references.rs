use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::dtcg::{DimensionUnit, DtcgValue};
use paintgun::resolver::{
    build_token_store_for_inputs, read_json_file, Input, ResolverDoc, ResolverError,
};

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("paintgun-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_json(path: &Path, value: serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(&value).expect("serialize json");
    fs::write(path, bytes).expect("write json");
}

fn dimension_value(token: &paintgun::resolver::ResolvedToken) -> (String, DimensionUnit) {
    match &token.value {
        DtcgValue::Dimension(d) => (d.value.0.clone(), d.unit.clone()),
        other => panic!(
            "expected dimension token, got {}",
            other.to_canonical_json_string()
        ),
    }
}

fn set_input(axis: &str, value: &str) -> Input {
    let mut input = BTreeMap::new();
    input.insert(axis.to_string(), value.to_string());
    input
}

#[test]
fn resolution_order_reference_objects_are_supported() {
    let root = temp_dir("resolver-order-ref-object");
    let tokens = root.join("tokens");
    fs::create_dir_all(&tokens).expect("tokens dir");

    write_json(
        &tokens.join("base.json"),
        serde_json::json!({
            "space": {
                "$type": "dimension",
                "md": { "$value": { "value": "4", "unit": "px" } }
            }
        }),
    );
    write_json(
        &tokens.join("dark.json"),
        serde_json::json!({
            "space": {
                "md": { "$value": { "value": "8", "unit": "px" } }
            }
        }),
    );

    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ { "$ref": "tokens/base.json" } ] }
            },
            "modifiers": {
                "theme": {
                    "contexts": {
                        "dark": [ { "$ref": "tokens/dark.json" } ]
                    }
                }
            },
            "resolutionOrder": [
                { "$ref": "#/sets/base" },
                { "$ref": "#/modifiers/theme" }
            ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let input = set_input("theme", "dark");
    let store = build_token_store_for_inputs(&doc, &resolver_path, &[input.clone()])
        .expect("build token store");
    let token = store
        .token_at("space.md", &input)
        .expect("resolved token space.md");
    let (value, unit) = dimension_value(token);
    assert_eq!(value, "8");
    assert_eq!(unit, DimensionUnit::Px);
}

#[test]
fn resolution_order_reference_objects_support_local_overrides() {
    let root = temp_dir("resolver-order-ref-overrides");
    let tokens = root.join("tokens");
    fs::create_dir_all(&tokens).expect("tokens dir");

    write_json(
        &tokens.join("base.json"),
        serde_json::json!({
            "space": {
                "$type": "dimension",
                "md": { "$value": { "value": "4", "unit": "px" } }
            }
        }),
    );
    write_json(
        &tokens.join("override.json"),
        serde_json::json!({
            "space": {
                "$type": "dimension",
                "md": { "$value": { "value": "10", "unit": "px" } }
            }
        }),
    );

    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ { "$ref": "tokens/base.json" } ] }
            },
            "resolutionOrder": [
                {
                    "$ref": "#/sets/base",
                    "sources": [ { "$ref": "tokens/override.json" } ]
                }
            ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect("build token store");
    let token = store
        .token_at("space.md", &Input::new())
        .expect("resolved token space.md");
    let (value, unit) = dimension_value(token);
    assert_eq!(value, "10");
    assert_eq!(unit, DimensionUnit::Px);
}

#[test]
fn resolution_order_unknown_reference_is_error() {
    let root = temp_dir("resolver-order-invalid-ref");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ {} ] }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/missing" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected invalid resolver ref");
    match err {
        ResolverError::InvalidResolverRef { reference, reason } => {
            assert_eq!(reference, "#/sets/missing");
            assert!(
                reason.contains("unknown set"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver ref error, got {other}"),
    }
}

#[test]
fn unknown_input_axis_or_value_is_error() {
    let root = temp_dir("resolver-invalid-input");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ {} ] }
            },
            "modifiers": {
                "theme": {
                    "contexts": {
                        "light": [ {} ],
                        "dark": [ {} ]
                    }
                }
            },
            "resolutionOrder": [
                { "$ref": "#/sets/base" },
                { "$ref": "#/modifiers/theme" }
            ]
        }),
    );
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");

    let bad_axis = set_input("unknown", "x");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[bad_axis])
        .expect_err("expected invalid resolver input");
    match err {
        ResolverError::InvalidResolverInput {
            axis,
            value,
            reason,
        } => {
            assert_eq!(axis, "unknown");
            assert_eq!(value, "x");
            assert!(
                reason.contains("unknown modifier axis"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver input error, got {other}"),
    }

    let bad_value = set_input("theme", "neon");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[bad_value])
        .expect_err("expected invalid resolver input");
    match err {
        ResolverError::InvalidResolverInput {
            axis,
            value,
            reason,
        } => {
            assert_eq!(axis, "theme");
            assert_eq!(value, "neon");
            assert!(
                reason.contains("unknown modifier context value"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver input error, got {other}"),
    }
}

#[test]
fn missing_required_modifier_input_is_error() {
    let root = temp_dir("resolver-missing-required-input");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ {} ] }
            },
            "modifiers": {
                "theme": {
                    "contexts": {
                        "light": [ {} ],
                        "dark": [ {} ]
                    }
                }
            },
            "resolutionOrder": [
                { "$ref": "#/sets/base" },
                { "$ref": "#/modifiers/theme" }
            ]
        }),
    );
    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");

    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected missing required modifier input");
    match err {
        ResolverError::InvalidResolverInput {
            axis,
            value,
            reason,
        } => {
            assert_eq!(axis, "theme");
            assert_eq!(value, "(missing)");
            assert!(
                reason.contains("missing required modifier input"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver input error, got {other}"),
    }
}

#[test]
fn source_reference_to_set_with_local_overrides_is_supported() {
    let root = temp_dir("resolver-source-local-set-ref");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "space": {
                                "$type": "dimension",
                                "md": { "$value": { "value": "4", "unit": "px" } }
                            }
                        }
                    ]
                }
            },
            "modifiers": {
                "theme": {
                    "contexts": {
                        "dark": [
                            {
                                "$ref": "#/sets/base",
                                "space": {
                                    "$type": "dimension",
                                    "md": { "$value": { "value": "8", "unit": "px" } }
                                }
                            }
                        ]
                    }
                }
            },
            "resolutionOrder": [ { "$ref": "#/modifiers/theme" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let input = set_input("theme", "dark");
    let store = build_token_store_for_inputs(&doc, &resolver_path, &[input.clone()])
        .expect("build token store");
    let token = store
        .token_at("space.md", &input)
        .expect("resolved token space.md");
    let (value, unit) = dimension_value(token);
    assert_eq!(value, "8");
    assert_eq!(unit, DimensionUnit::Px);
}

#[test]
fn source_reference_to_modifier_is_rejected() {
    let root = temp_dir("resolver-source-modifier-ref-rejected");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": { "sources": [ { "$ref": "#/modifiers/theme" } ] }
            },
            "modifiers": {
                "theme": {
                    "contexts": {
                        "dark": [ {} ]
                    }
                }
            },
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[set_input("theme", "dark")])
        .expect_err("expected invalid resolver ref");
    match err {
        ResolverError::InvalidResolverRef { reference, reason } => {
            assert_eq!(reference, "#/modifiers/theme");
            assert!(
                reason.contains("sources may not reference modifiers"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver ref error, got {other}"),
    }
}

#[test]
fn token_store_build_fails_fast_on_alias_errors() {
    let root = temp_dir("resolver-fail-fast-alias");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "color": {
                                "$type": "number",
                                "a": { "$value": "{color.missing}" }
                            }
                        }
                    ]
                }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected unresolved alias error");
    match err {
        ResolverError::UnresolvedAlias { path, r#ref } => {
            assert_eq!(path, "color.a");
            assert_eq!(r#ref, "color.missing");
        }
        other => panic!("expected unresolved alias error, got {other}"),
    }
}

#[test]
fn inline_resolution_order_entries_and_optional_root_maps_are_supported() {
    let root = temp_dir("resolver-inline-order");
    let tokens = root.join("tokens");
    fs::create_dir_all(&tokens).expect("tokens dir");

    write_json(
        &tokens.join("base.json"),
        serde_json::json!({
            "space": {
                "$type": "dimension",
                "md": { "$value": { "value": "4", "unit": "px" } }
            }
        }),
    );
    write_json(
        &tokens.join("dark.json"),
        serde_json::json!({
            "space": {
                "md": { "$value": { "value": "12", "unit": "px" } }
            }
        }),
    );

    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "resolutionOrder": [
                {
                    "type": "set",
                    "name": "base",
                    "sources": [ { "$ref": "tokens/base.json" } ]
                },
                {
                    "type": "modifier",
                    "name": "theme",
                    "contexts": {
                        "dark": [ { "$ref": "tokens/dark.json" } ],
                        "light": []
                    },
                    "default": "light"
                }
            ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let input = set_input("theme", "dark");
    let store = build_token_store_for_inputs(&doc, &resolver_path, &[input.clone()])
        .expect("build token store");
    let token = store
        .token_at("space.md", &input)
        .expect("resolved token space.md");
    let (value, unit) = dimension_value(token);
    assert_eq!(value, "12");
    assert_eq!(unit, DimensionUnit::Px);
}

#[test]
fn token_store_build_fails_fast_on_type_canonicalization_errors() {
    let root = temp_dir("resolver-fail-fast-canonicalization");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "dimension": {
                                "space": {
                                    "md": {
                                        "$type": "dimension",
                                        "$value": { "value": "8" }
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected canonicalization invalid type error");
    match err {
        ResolverError::InvalidType { path, reason, .. } => {
            assert_eq!(path, "dimension.space.md");
            assert!(
                reason.contains("missing unit"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid type error, got {other}"),
    }
}

#[test]
fn token_store_build_rejects_invalid_token_name_segments() {
    let root = temp_dir("resolver-invalid-token-name");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "color": {
                                "$type": "color",
                                "primary.dark": {
                                    "$value": {
                                        "colorSpace": "srgb",
                                        "components": [0.1, 0.2, 0.3]
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected invalid name error");
    match err {
        ResolverError::InvalidName { path, name, reason } => {
            assert_eq!(path, "color");
            assert_eq!(name, "primary.dark");
            assert!(
                reason.contains("must not contain '.'"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid name error, got {other}"),
    }
}

#[test]
fn token_store_build_rejects_unknown_dollar_prefixed_names() {
    let root = temp_dir("resolver-invalid-dollar-name");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "$brand": {
                                "primary": {
                                    "$type": "color",
                                    "$value": {
                                        "colorSpace": "srgb",
                                        "components": [0.1, 0.2, 0.3]
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let err = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect_err("expected invalid name error");
    match err {
        ResolverError::InvalidName { path, name, reason } => {
            assert_eq!(path, "(root)");
            assert_eq!(name, "$brand");
            assert!(
                reason.contains("must not begin with '$'"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid name error, got {other}"),
    }
}

#[test]
fn token_store_build_accepts_reserved_dtcg_properties() {
    let root = temp_dir("resolver-allowed-dtcg-properties");
    let resolver_path = root.join("resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
            "version": "2025.10",
            "sets": {
                "base": {
                    "sources": [
                        {
                            "color": {
                                "$description": "base palette",
                                "$extensions": {
                                    "org.example.paintgun": {
                                        "source": "fixture"
                                    }
                                },
                                "primary": {
                                    "$type": "color",
                                    "$description": "primary brand",
                                    "$extensions": {
                                        "org.example.paintgun": {
                                            "semantic": true
                                        }
                                    },
                                    "$value": {
                                        "colorSpace": "srgb",
                                        "components": [0.1, 0.2, 0.3]
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "modifiers": {},
            "resolutionOrder": [ { "$ref": "#/sets/base" } ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    let store = build_token_store_for_inputs(&doc, &resolver_path, &[Input::new()])
        .expect("reserved properties should be accepted");
    let token = store
        .token_at("color.primary", &Input::new())
        .expect("resolved token");
    assert_eq!(token.path, "color.primary");
}
