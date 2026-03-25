use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use paintgun::contexts::{layered_inputs, plan_inputs, ContextMode};
use paintgun::resolver::{
    axes_from_doc, axes_relevant_to_tokens, build_token_store, build_token_store_for_inputs,
    read_json_file, supporting_inputs_for_selection, ResolverDoc, ResolverError,
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

fn build_fixture(root: &Path) -> (ResolverDoc, PathBuf) {
    let tokens_dir = root.join("tokens");
    fs::create_dir_all(&tokens_dir).expect("tokens dir");

    write_json(
        &tokens_dir.join("base.tokens.json"),
        serde_json::json!({
          "color": {
            "surface": {
              "bg": {
                "$type": "color",
                "$value": { "colorSpace": "srgb", "components": [1, 1, 1], "alpha": 1 }
              }
            }
          },
          "dimension": {
            "space": { "md": { "$type": "dimension", "$value": { "value": "8", "unit": "px" } } },
            "radius": { "md": { "$type": "dimension", "$value": { "value": "4", "unit": "px" } } }
          }
        }),
    );
    write_json(
        &tokens_dir.join("theme.dark.tokens.json"),
        serde_json::json!({
          "color": {
            "surface": {
              "bg": {
                "$type": "color",
                "$value": { "colorSpace": "srgb", "components": [0.1, 0.1, 0.1], "alpha": 1 }
              }
            }
          }
        }),
    );
    write_json(
        &tokens_dir.join("theme.light.tokens.json"),
        serde_json::json!({}),
    );
    write_json(
        &tokens_dir.join("density.compact.tokens.json"),
        serde_json::json!({
          "dimension": { "space": { "md": { "$type": "dimension", "$value": { "value": "6", "unit": "px" } } } }
        }),
    );
    write_json(
        &tokens_dir.join("density.comfortable.tokens.json"),
        serde_json::json!({}),
    );
    write_json(
        &tokens_dir.join("motion.reduced.tokens.json"),
        serde_json::json!({
          "dimension": { "radius": { "md": { "$type": "dimension", "$value": { "value": "3", "unit": "px" } } } }
        }),
    );
    write_json(
        &tokens_dir.join("motion.normal.tokens.json"),
        serde_json::json!({}),
    );

    let resolver_path = root.join("fixture.resolver.json");
    write_json(
        &resolver_path,
        serde_json::json!({
          "name": "fixture-pack",
          "version": "2025.10",
          "sets": {
            "base": { "sources": [ { "$ref": "tokens/base.tokens.json" } ] }
          },
          "modifiers": {
            "theme": {
              "contexts": {
                "dark": [ { "$ref": "tokens/theme.dark.tokens.json" } ],
                "light": [ { "$ref": "tokens/theme.light.tokens.json" } ]
              }
            },
            "density": {
              "contexts": {
                "compact": [ { "$ref": "tokens/density.compact.tokens.json" } ],
                "comfortable": [ { "$ref": "tokens/density.comfortable.tokens.json" } ]
              }
            },
            "motion": {
              "contexts": {
                "reduced": [ { "$ref": "tokens/motion.reduced.tokens.json" } ],
                "normal": [ { "$ref": "tokens/motion.normal.tokens.json" } ]
              }
            }
          },
          "resolutionOrder": [
            { "$ref": "#/sets/base" },
            { "$ref": "#/modifiers/theme" },
            { "$ref": "#/modifiers/density" },
            { "$ref": "#/modifiers/motion" }
          ]
        }),
    );

    let doc: ResolverDoc = read_json_file(&resolver_path).expect("resolver doc");
    (doc, resolver_path)
}

#[test]
fn resolver_build_uses_planned_context_inputs() {
    let root = temp_dir("resolver-context-modes");
    let (doc, resolver_path) = build_fixture(&root);

    let axes = axes_from_doc(&doc);
    let full_inputs = plan_inputs(ContextMode::FullOnly, &axes, None);
    let partial_inputs = plan_inputs(ContextMode::Partial, &axes, None);

    let contract_tokens = BTreeSet::from(["color.surface.bg".to_string()]);
    let relevant_axes =
        axes_relevant_to_tokens(&doc, &resolver_path, &contract_tokens).expect("relevant axes");
    assert_eq!(
        relevant_axes,
        BTreeSet::from(["theme".to_string()]),
        "only theme should affect contract token in fixture"
    );
    let contract_inputs = plan_inputs(ContextMode::FromContracts, &axes, Some(&relevant_axes));

    assert_eq!(full_inputs.len(), 8, "3 axes × 2 values");
    assert_eq!(partial_inputs.len(), 27, "(1+2)^3 partial contexts");
    assert_eq!(
        contract_inputs.len(),
        3,
        "base + single-axis contexts for one relevant axis"
    );

    let full_store =
        build_token_store_for_inputs(&doc, &resolver_path, &full_inputs).expect("full store");
    let partial_store = build_token_store(&doc, &resolver_path).expect("partial store");
    let contract_err = build_token_store_for_inputs(&doc, &resolver_path, &contract_inputs)
        .expect_err("contract contexts without required modifiers should be rejected");
    let supporting_contract_inputs = supporting_inputs_for_selection(&doc, &contract_inputs);
    let supporting_layered_inputs =
        supporting_inputs_for_selection(&doc, &layered_inputs(&axes, None));

    assert_eq!(full_store.resolved_by_ctx.len(), 8);
    assert_eq!(partial_store.resolved_by_ctx.len(), 27);
    assert_eq!(
        supporting_contract_inputs.len(),
        8,
        "missing required modifiers should expand to supporting full contexts"
    );
    assert_eq!(
        supporting_layered_inputs.len(),
        8,
        "layered backend-required inputs should also expand to valid explicit contexts"
    );
    match contract_err {
        ResolverError::InvalidResolverInput {
            axis,
            value,
            reason,
        } => {
            assert_eq!(axis, "density");
            assert_eq!(value, "(missing)");
            assert!(
                reason.contains("missing required modifier input"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected invalid resolver input error, got {other}"),
    }

    let contract_scoped_store =
        build_token_store_for_inputs(&doc, &resolver_path, &supporting_contract_inputs)
            .expect("supporting contract inputs should build");
    assert_eq!(
        contract_scoped_store.resolved_by_ctx.len(),
        8,
        "supporting inputs should preserve full valid resolver coverage"
    );

    for (ctx, toks) in &full_store.resolved_by_ctx {
        let from_partial = partial_store
            .resolved_by_ctx
            .get(ctx)
            .expect("full context should exist in partial store");
        let mut lhs: Vec<(String, String, String, String)> = from_partial
            .iter()
            .map(|t| {
                (
                    t.path.clone(),
                    t.ty.to_string(),
                    t.value.to_canonical_json_string(),
                    t.source.clone(),
                )
            })
            .collect();
        let mut rhs: Vec<(String, String, String, String)> = toks
            .iter()
            .map(|t| {
                (
                    t.path.clone(),
                    t.ty.to_string(),
                    t.value.to_canonical_json_string(),
                    t.source.clone(),
                )
            })
            .collect();
        lhs.sort();
        rhs.sort();
        assert_eq!(
            lhs, rhs,
            "overlapping context `{ctx}` should resolve identically"
        );
    }
}
