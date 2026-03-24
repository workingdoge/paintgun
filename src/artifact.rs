//! Artifact I/O for paintgun.
//!
//! The key artifact is `resolved.json`: a platform-neutral export of the
//! spec-resolved token sets per context.
//!
//! This file is intentionally **target-agnostic** (structured DTCG values).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::dtcg::{DtcgType, DtcgValue};
use crate::resolver::{context_key, parse_context_key, Input, ResolvedToken, TokenStore};

/// Platform-neutral export of a resolved token store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedExport {
    pub spec: String,
    pub tool: String,
    pub axes: BTreeMap<String, Vec<String>>,
    pub contexts: Vec<ResolvedContextExport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedContextExport {
    pub context: String,
    pub input: Input,
    pub tokens: Vec<ResolvedTokenExport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedTokenExport {
    pub path: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: DtcgValue,
}

impl ResolvedExport {
    /// Convert a `TokenStore` into a stable JSON export.
    pub fn from_store(store: &TokenStore) -> Self {
        // Deterministic context order
        let mut keys: Vec<String> = store.resolved_by_ctx.keys().cloned().collect();
        keys.sort();

        let mut contexts: Vec<ResolvedContextExport> = Vec::new();
        for key in keys {
            let input = parse_context_key(&key);
            let mut tokens = store
                .resolved_by_ctx
                .get(&key)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|t| ResolvedTokenExport {
                    path: t.path,
                    ty: t.ty.to_string(),
                    value: t.value,
                })
                .collect::<Vec<_>>();
            tokens.sort_by(|a, b| a.path.cmp(&b.path));

            contexts.push(ResolvedContextExport {
                context: key,
                input,
                tokens,
            });
        }

        ResolvedExport {
            spec: "DTCG 2025.10".to_string(),
            tool: "paintgun".to_string(),
            axes: store.axes.clone(),
            contexts,
        }
    }

    /// Convert a resolved export back into an in-memory store.
    pub fn into_store(self) -> Result<TokenStore, String> {
        let mut resolved_by_ctx: std::collections::HashMap<String, Vec<ResolvedToken>> =
            std::collections::HashMap::new();

        for c in self.contexts {
            let mut toks: Vec<ResolvedToken> = Vec::new();
            for t in c.tokens {
                let ty: DtcgType =
                    t.ty.parse()
                        .map_err(|e: String| format!("invalid token type at {}: {e}", t.path))?;
                toks.push(ResolvedToken {
                    path: t.path,
                    ty,
                    value: t.value,
                    source: c.context.clone(),
                });
            }
            toks.sort_by(|a, b| a.path.cmp(&b.path));
            resolved_by_ctx.insert(c.context, toks);
        }

        Ok(TokenStore {
            axes: self.axes,
            resolved_by_ctx,
        })
    }
}

pub fn write_resolved_json(path: &Path, store: &TokenStore) -> Result<(), String> {
    let export = ResolvedExport::from_store(store);
    let bytes = serde_json::to_vec_pretty(&export).map_err(|e| e.to_string())?;
    fs::write(path, bytes).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn read_resolved_json(path: &Path) -> Result<TokenStore, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let export: ResolvedExport = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    export.into_store()
}

/// Helper to fetch a token value from a store.
pub fn token_value_at(
    store: &TokenStore,
    token_path: &str,
    input: &Input,
) -> Option<(DtcgType, DtcgValue)> {
    store
        .token_at(token_path, input)
        .map(|t| (t.ty, t.value.clone()))
}

/// Canonical stable context key for an input.
pub fn stable_context_key(input: &Input) -> String {
    context_key(input)
}
