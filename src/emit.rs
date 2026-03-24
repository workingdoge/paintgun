use crate::policy::Policy;
use crate::resolver::TokenStore;
pub use paintgun_emit::{
    compile_component_css_with_layers_lookup, emit_kotlin_module_scaffold,
    emit_store_kotlin_with_lookup, emit_store_swift_with_lookup, emit_swift_package_scaffold,
    emit_tokens_d_ts, emit_value, stable_context_key, Contract, CssEmitter, Delta, EmissionToken,
    Emitter, KotlinEmitter, LayerDef, SlotDef, SwiftEmitter, ANDROID_COMPOSE_EMITTER_API_VERSION,
    KOTLIN_EMITTER_API_VERSION, SWIFT_EMITTER_API_VERSION,
};

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
