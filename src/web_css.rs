use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::dtcg::{DtcgType, DtcgValue};
use crate::emit::{emit_tokens_d_ts, emit_value, Contract, CssEmitter};
use crate::policy::{normalize_value, Policy};
use crate::resolver::{Input, ResolverDoc, TokenStore};

#[derive(Clone, Debug)]
struct CssLayer {
    name: String,
    input: Input,
    selector: String,
}

pub fn css_custom_property_name(token_path: &str) -> String {
    let mut out = String::from("--paintgun-");
    let mut last_was_dash = false;
    for ch in token_path.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if !last_was_dash {
                out.push('-');
                last_was_dash = true;
            }
        } else {
            out.push(normalized);
            last_was_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn ordered_modifier_names_for_doc(doc: &ResolverDoc) -> Vec<String> {
    let mut mod_names: Vec<String> = Vec::new();
    for entry in &doc.resolution_order {
        if let Some(name) = entry.modifier_name() {
            if !mod_names.iter().any(|m| m == &name) {
                mod_names.push(name);
            }
        }
    }
    if mod_names.is_empty() {
        mod_names.extend(
            doc.all_modifiers()
                .into_iter()
                .map(|(name, _)| name.to_string()),
        );
        mod_names.sort();
    }
    mod_names
}

fn ordered_modifier_names_from_axes(axes: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut mod_names: Vec<String> = axes.keys().cloned().collect();
    mod_names.sort();
    mod_names
}

fn layer_order(mod_names: &[String]) -> Vec<String> {
    let mut out = vec!["base".to_string()];
    out.extend(mod_names.iter().cloned());
    for i in 0..mod_names.len() {
        for j in (i + 1)..mod_names.len() {
            out.push(format!("{}-{}", mod_names[i], mod_names[j]));
        }
    }
    out
}

fn build_token_layers(mod_names: &[String], axes: &BTreeMap<String, Vec<String>>) -> Vec<CssLayer> {
    let mut layers = Vec::new();
    layers.push(CssLayer {
        name: "base".to_string(),
        input: BTreeMap::new(),
        selector: ":root".to_string(),
    });

    for mod_name in mod_names {
        let ctxs = axes.get(mod_name).cloned().unwrap_or_default();
        for ctx in ctxs {
            let mut input = BTreeMap::new();
            input.insert(mod_name.clone(), ctx.clone());
            layers.push(CssLayer {
                name: mod_name.clone(),
                input,
                selector: format!(":root[data-{mod_name}=\"{ctx}\"]"),
            });
        }
    }

    if mod_names.len() >= 2 {
        for i in 0..mod_names.len() {
            for j in (i + 1)..mod_names.len() {
                let a = &mod_names[i];
                let b = &mod_names[j];
                let ctx_a = axes.get(a).cloned().unwrap_or_default();
                let ctx_b = axes.get(b).cloned().unwrap_or_default();
                for va in &ctx_a {
                    for vb in &ctx_b {
                        let mut input = BTreeMap::new();
                        input.insert(a.clone(), va.clone());
                        input.insert(b.clone(), vb.clone());
                        layers.push(CssLayer {
                            name: format!("{a}-{b}"),
                            input,
                            selector: format!(":root[data-{a}=\"{va}\"][data-{b}=\"{vb}\"]"),
                        });
                    }
                }
            }
        }
    }

    layers
}

fn emit_layer_block(layer_name: &str, selector: &str, lines: &[String]) -> Option<String> {
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "@layer {layer_name} {{\n  {selector} {{\n{}\n  }}\n}}",
        lines.join("\n")
    ))
}

fn emit_css_token_stylesheet(
    layer_order: &[String],
    layers: &[CssLayer],
    store: &TokenStore,
    policy: &Policy,
) -> String {
    let emitter = CssEmitter {
        color_policy: policy.css_color.clone(),
    };
    let mut blocks = Vec::new();
    let mut baseline: HashMap<String, (DtcgType, DtcgValue)> = HashMap::new();

    for layer in layers {
        let mut current: HashMap<String, (DtcgType, DtcgValue)> = HashMap::new();
        for token in store.tokens_at(&layer.input) {
            let norm = normalize_value(policy, token.ty, &token.value);
            current.insert(token.path.clone(), (token.ty, norm));
        }

        let mut paths: Vec<String> = current.keys().cloned().collect();
        paths.sort();
        let mut lines = Vec::new();
        for path in paths {
            let (ty, value) = current.get(&path).expect("token path must exist");
            let changed = match baseline.get(&path) {
                None => true,
                Some((prev_ty, prev_value)) => prev_ty != ty || prev_value != value,
            };
            if changed {
                lines.push(format!(
                    "    {}: {};",
                    css_custom_property_name(&path),
                    emit_value(&emitter, *ty, value, &path)
                ));
            }
        }

        if let Some(block) =
            emit_layer_block(&format!("tokens.{}", layer.name), &layer.selector, &lines)
        {
            blocks.push(block);
        }

        for (path, typed_value) in current {
            baseline.insert(path, typed_value);
        }
    }

    let ordered_layers = layer_order
        .iter()
        .map(|name| format!("tokens.{name}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("@layer {ordered_layers};\n\n{}\n", blocks.join("\n\n"))
}

pub fn emit_css_token_stylesheet_for_build(
    doc: &ResolverDoc,
    store: &TokenStore,
    policy: &Policy,
) -> String {
    let mod_names = ordered_modifier_names_for_doc(doc);
    let axes = &store.axes;
    let layers = build_token_layers(&mod_names, axes);
    let order = layer_order(&mod_names);
    emit_css_token_stylesheet(&order, &layers, store, policy)
}

pub fn emit_css_token_stylesheet_for_compose(
    axes: &BTreeMap<String, Vec<String>>,
    store: &TokenStore,
    policy: &Policy,
) -> String {
    let mod_names = ordered_modifier_names_from_axes(axes);
    let layers = build_token_layers(&mod_names, axes);
    let order = layer_order(&mod_names);
    emit_css_token_stylesheet(&order, &layers, store, policy)
}

pub fn emit_component_package_stylesheet(contracts: &[Contract]) -> String {
    let mut sorted_contracts = contracts.to_vec();
    sorted_contracts.sort_by(|lhs, rhs| lhs.component.cmp(&rhs.component));

    let mut out = String::new();
    out.push_str("@layer components {\n");
    for contract in &sorted_contracts {
        let mut props: BTreeSet<(String, String)> = BTreeSet::new();
        for slot in contract.slots.values() {
            props.insert((slot.property.clone(), slot.token.clone()));
        }

        out.push_str(&format!("  /* ═ {} ═ */\n", contract.component));
        out.push_str(&format!("  {} {{\n", contract.component));
        for (property, token) in props {
            out.push_str(&format!(
                "    {}: var({});\n",
                property,
                css_custom_property_name(&token)
            ));
        }
        out.push_str("  }\n");
    }
    out.push_str("}\n");
    out
}

pub fn emit_component_package_types(contracts: &[Contract]) -> String {
    emit_tokens_d_ts(contracts)
}

pub fn assemble_css_compat_stylesheet(token_css: &str, component_css: &str) -> String {
    if component_css.trim().is_empty() {
        return token_css.to_string();
    }
    format!("{token_css}\n{component_css}")
}
