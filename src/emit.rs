use std::collections::BTreeMap;

use crate::policy::Policy;
use crate::resolver::{ResolverDoc, TokenStore};

pub use tbp_emit::{
    build_layer_defs_for_ordered_modifiers, build_layer_defs_from_axes,
    compile_component_css_with_layers_lookup, emit_kotlin_module_scaffold,
    emit_store_kotlin_with_lookup, emit_store_swift_with_lookup, emit_swift_package_scaffold,
    emit_tokens_d_ts, emit_value, stable_context_key, Contract, CssEmitter, Delta, EmissionToken,
    Emitter, KotlinEmitter, LayerDef, SlotDef, SwiftEmitter, KOTLIN_EMITTER_API_VERSION,
    SWIFT_EMITTER_API_VERSION,
};

pub fn build_layer_defs(doc: &ResolverDoc) -> Vec<LayerDef> {
    let mut axes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (mod_name, modifier) in doc.all_modifiers() {
        let mut vals: Vec<String> = modifier.contexts.keys().cloned().collect();
        vals.sort();
        axes.insert(mod_name.to_string(), vals);
    }

    let mut mod_names: Vec<String> = Vec::new();
    for entry in &doc.resolution_order {
        if let Some(name) = entry.modifier_name() {
            if !mod_names.iter().any(|m| m == &name) {
                mod_names.push(name);
            }
        }
    }
    if mod_names.is_empty() {
        mod_names = axes.keys().cloned().collect();
    }

    build_layer_defs_for_ordered_modifiers(&mod_names, &axes)
}

pub fn compile_component_css(
    contract: &Contract,
    doc: &ResolverDoc,
    store: &TokenStore,
    policy: &Policy,
    emitter: &CssEmitter,
) -> String {
    let layer_defs = build_layer_defs(doc);
    compile_component_css_with_layers(contract, store, policy, emitter, &layer_defs)
}

pub fn compile_component_css_with_layers(
    contract: &Contract,
    store: &TokenStore,
    policy: &Policy,
    emitter: &CssEmitter,
    layer_defs: &[LayerDef],
) -> String {
    compile_component_css_with_layers_lookup(
        contract,
        policy,
        emitter,
        layer_defs,
        |path, input| {
            store
                .token_at(path, input)
                .map(|tok| (tok.ty, tok.value.clone()))
        },
    )
}

pub fn emit_store_swift(store: &TokenStore, policy: &Policy) -> String {
    emit_store_swift_with_lookup(&store.axes, policy, |input| {
        store
            .tokens_at(input)
            .iter()
            .map(|t| EmissionToken {
                path: t.path.clone(),
                ty: t.ty,
                value: t.value.clone(),
            })
            .collect()
    })
}

pub fn emit_store_kotlin(store: &TokenStore, policy: &Policy) -> String {
    emit_store_kotlin_with_lookup(&store.axes, policy, |input| {
        store
            .tokens_at(input)
            .iter()
            .map(|t| EmissionToken {
                path: t.path.clone(),
                ty: t.ty,
                value: t.value.clone(),
            })
            .collect()
    })
}
