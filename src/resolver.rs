use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;
use tbp_resolver_kernel::{AliasError, CanonicalizeError, ExtendsError, FlattenError};

use crate::dtcg::{DtcgType, JValue};
use crate::resolver_io::{
    axes_relevant_to_tokens_with_io, flatten_with_io, load_source_with_io, FsResolverIo,
};
pub use tbp_resolver_model::{
    axes_from_doc, context_key, dedup_inputs_for_axes, parse_context_key, validate_input_selection,
    Input, InputSelectionError, MaterializedToken, ResolvedToken, ResolverDoc, ResolverModifier,
    ResolverModifierContext, ResolverOrderRefObject, ResolverSet, ResolverSource, TokenStore,
};

//──────────────────────────────────────────────────────────────────────────────
// Errors
//──────────────────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum ResolverError {
    #[error("failed to read file {path}: {cause}")]
    ReadFile { path: String, cause: String },

    #[error("failed to parse JSON {path}: {cause}")]
    ParseJson { path: String, cause: String },

    #[error("circular $extends chain: {chain:?}")]
    CircularExtends { chain: Vec<String> },

    #[error("circular alias chain: {chain:?}")]
    CircularAlias { chain: Vec<String> },

    #[error("unresolved alias: token {path} refers to {r#ref}")]
    UnresolvedAlias { path: String, r#ref: String },

    #[error("unsupported alias form: token {path} refers to {r#ref} ({reason})")]
    UnsupportedAliasForm {
        path: String,
        r#ref: String,
        reason: String,
    },

    #[error("invalid type at {path} ({ty}): {reason}")]
    InvalidType {
        path: String,
        ty: DtcgType,
        reason: String,
    },

    #[error("unsafe source path {path}: {reason}")]
    UnsafePath { path: String, reason: String },

    #[error("invalid resolver reference {reference}: {reason}")]
    InvalidResolverRef { reference: String, reason: String },

    #[error("invalid resolver input {axis}:{value}: {reason}")]
    InvalidResolverInput {
        axis: String,
        value: String,
        reason: String,
    },

    #[error("circular resolver reference chain: {chain:?}")]
    CircularResolverRef { chain: Vec<String> },
}

//──────────────────────────────────────────────────────────────────────────────
// JSON helpers
//──────────────────────────────────────────────────────────────────────────────

pub fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ResolverError> {
    let bytes = fs::read(path).map_err(|e| ResolverError::ReadFile {
        path: path.display().to_string(),
        cause: e.to_string(),
    })?;

    serde_json::from_slice(&bytes).map_err(|e| ResolverError::ParseJson {
        path: path.display().to_string(),
        cause: e.to_string(),
    })
}

fn map_extends_error(err: ExtendsError) -> ResolverError {
    match err {
        ExtendsError::CircularExtends { chain } => ResolverError::CircularExtends { chain },
        ExtendsError::InvalidType { path, reason } => ResolverError::InvalidType {
            path,
            ty: DtcgType::Typography,
            reason,
        },
    }
}

fn map_alias_error(err: AliasError) -> ResolverError {
    match err {
        AliasError::CircularAlias { chain } => ResolverError::CircularAlias { chain },
        AliasError::UnresolvedAlias { path, r#ref } => {
            ResolverError::UnresolvedAlias { path, r#ref }
        }
        AliasError::UnsupportedAliasForm {
            path,
            r#ref,
            reason,
        } => ResolverError::UnsupportedAliasForm {
            path,
            r#ref,
            reason,
        },
        AliasError::InvalidType { path, ty, reason } => {
            ResolverError::InvalidType { path, ty, reason }
        }
    }
}

fn map_canonicalize_error(err: CanonicalizeError) -> ResolverError {
    match err {
        CanonicalizeError::InvalidType { path, ty, reason } => {
            ResolverError::InvalidType { path, ty, reason }
        }
    }
}

//──────────────────────────────────────────────────────────────────────────────
// Load sources
//──────────────────────────────────────────────────────────────────────────────

fn map_flatten_error(err: FlattenError) -> ResolverError {
    match err {
        FlattenError::CircularResolverRef { chain } => ResolverError::CircularResolverRef { chain },
        FlattenError::InvalidResolverRef { reference, reason } => {
            ResolverError::InvalidResolverRef { reference, reason }
        }
        FlattenError::UnsafePath { path, reason } => ResolverError::UnsafePath { path, reason },
        FlattenError::ReadFile { path, cause } => ResolverError::ReadFile { path, cause },
        FlattenError::ParseJson { path, cause } => ResolverError::ParseJson { path, cause },
        FlattenError::InvalidResolverInput {
            axis,
            value,
            reason,
        } => ResolverError::InvalidResolverInput {
            axis,
            value,
            reason,
        },
    }
}

pub(crate) fn load_source(
    doc: &ResolverDoc,
    source: &ResolverSource,
    base_dir: &Path,
) -> Result<JValue, ResolverError> {
    load_source_with_io(&FsResolverIo, doc, source, base_dir).map_err(map_flatten_error)
}

pub fn flatten(doc: &ResolverDoc, input: &Input, base_dir: &Path) -> Result<JValue, ResolverError> {
    flatten_with_io(&FsResolverIo, doc, input, base_dir).map_err(map_flatten_error)
}

//──────────────────────────────────────────────────────────────────────────────
// $extends resolution (Format Module)
//──────────────────────────────────────────────────────────────────────────────

pub fn resolve_extends(tree: &JValue) -> Result<JValue, ResolverError> {
    tbp_resolver_kernel::resolve_extends(tree).map_err(map_extends_error)
}

//──────────────────────────────────────────────────────────────────────────────
// Materialize (flatten groups to token list)
//──────────────────────────────────────────────────────────────────────────────

pub fn materialize(tree: &JValue, source: &str) -> Vec<MaterializedToken> {
    tbp_resolver_kernel::materialize(tree, source)
}

//──────────────────────────────────────────────────────────────────────────────
// Explicit token definitions (presence of $value)
//──────────────────────────────────────────────────────────────────────────────

/// Collect token paths that are *explicitly defined* in the given token tree.
///
/// "Explicit" here means: there is a `$value` node at that path (including `$root`).
///
/// Notes:
/// - This intentionally does **not** expand `$extends` across other documents.
/// - Used to build the authored subposet S for Kan/BC analysis.
pub fn collect_explicit_token_paths(tree: &JValue) -> HashSet<String> {
    tbp_resolver_kernel::collect_explicit_token_paths(tree)
}

/// Collect token paths that are *explicitly defined* in the given token tree,
/// along with a JSON Pointer to the defining `$value`.
///
/// Returned map: tokenPath -> jsonPointer (to `$value`).
///
/// This is used for provenance in composability witnesses and multi-pack composition.
pub fn collect_explicit_token_defs(tree: &JValue) -> HashMap<String, String> {
    tbp_resolver_kernel::collect_explicit_token_defs(tree)
}

//──────────────────────────────────────────────────────────────────────────────
// Alias resolution
//──────────────────────────────────────────────────────────────────────────────

pub fn resolve_aliases(
    tokens: &[MaterializedToken],
) -> Result<Vec<ResolvedToken>, Vec<ResolverError>> {
    tbp_resolver_kernel::resolve_aliases(tokens)
        .map_err(|errs| errs.into_iter().map(map_alias_error).collect())
}

//──────────────────────────────────────────────────────────────────────────────
// Type validation + canonicalization
//──────────────────────────────────────────────────────────────────────────────

pub fn canonicalize_token(token: &ResolvedToken) -> Result<ResolvedToken, ResolverError> {
    tbp_resolver_kernel::canonicalize_token(token).map_err(map_canonicalize_error)
}

pub fn axes_relevant_to_tokens(
    doc: &ResolverDoc,
    resolver_path: &Path,
    token_paths: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ResolverError> {
    let base_dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    axes_relevant_to_tokens_with_io(&FsResolverIo, doc, base_dir, token_paths)
        .map_err(map_flatten_error)
}

pub fn build_token_store_for_inputs(
    doc: &ResolverDoc,
    resolver_path: &Path,
    inputs: &[Input],
) -> Result<TokenStore, ResolverError> {
    crate::resolver_runtime::build_token_store_for_inputs(doc, resolver_path, inputs)
}

pub fn build_token_store(
    doc: &ResolverDoc,
    resolver_path: &Path,
) -> Result<TokenStore, ResolverError> {
    crate::resolver_runtime::build_token_store(doc, resolver_path)
}
