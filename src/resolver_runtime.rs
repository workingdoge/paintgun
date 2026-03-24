use std::collections::HashMap;
use std::path::Path;

use paintgun_resolver_kernel::{AliasError, CanonicalizeError, ExtendsError, FlattenError};
use paintgun_resolver_model::{
    axes_from_doc, context_key, dedup_inputs_for_axes, validate_input_selection, Input,
    InputSelectionError, ResolvedToken, ResolverDoc, TokenStore,
};

use crate::resolver::ResolverError;
use crate::resolver_io::{flatten_with_io, FsResolverIo};

fn map_extends_error(err: ExtendsError) -> ResolverError {
    match err {
        ExtendsError::CircularExtends { chain } => ResolverError::CircularExtends { chain },
        ExtendsError::InvalidType { path, reason } => ResolverError::InvalidType {
            path,
            ty: paintgun_dtcg::DtcgType::Typography,
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

fn map_input_selection_error(err: InputSelectionError) -> ResolverError {
    match err {
        InputSelectionError::UnknownAxis { axis, value } => ResolverError::InvalidResolverInput {
            axis,
            value,
            reason: "unknown modifier axis".to_string(),
        },
        InputSelectionError::UnknownContextValue { axis, value } => {
            ResolverError::InvalidResolverInput {
                axis,
                value,
                reason: "unknown modifier context value".to_string(),
            }
        }
    }
}

pub fn build_token_store_for_inputs(
    doc: &ResolverDoc,
    resolver_path: &Path,
    inputs: &[Input],
) -> Result<TokenStore, ResolverError> {
    let base_dir = resolver_path.parent().unwrap_or_else(|| Path::new("."));
    let axes = axes_from_doc(doc);
    for input in inputs {
        validate_input_selection(doc, input).map_err(map_input_selection_error)?;
    }
    let planned_inputs = dedup_inputs_for_axes(inputs);

    let mut resolved_by_ctx: HashMap<String, Vec<ResolvedToken>> = HashMap::new();

    for input in planned_inputs {
        let key = context_key(&input);
        let tree =
            flatten_with_io(&FsResolverIo, doc, &input, base_dir).map_err(map_flatten_error)?;
        let extended =
            paintgun_resolver_kernel::resolve_extends(&tree).map_err(map_extends_error)?;

        let source = key.clone();
        let materialized = paintgun_resolver_kernel::materialize(&extended, &source);
        let resolved = paintgun_resolver_kernel::resolve_aliases(&materialized)
            .map_err(|errs| errs.into_iter().map(map_alias_error).collect::<Vec<_>>())
            .map_err(|errs| errs.into_iter().next().expect("non-empty alias error set"))?;

        // Canonicalize values by type
        let mut canonical: Vec<ResolvedToken> = Vec::new();
        for t in resolved {
            canonical.push(
                paintgun_resolver_kernel::canonicalize_token(&t).map_err(map_canonicalize_error)?,
            );
        }

        resolved_by_ctx.insert(key, canonical);
    }

    Ok(TokenStore {
        axes,
        resolved_by_ctx,
    })
}

pub fn build_token_store(
    doc: &ResolverDoc,
    resolver_path: &Path,
) -> Result<TokenStore, ResolverError> {
    let axes = axes_from_doc(doc);
    let inputs = crate::contexts::partial_inputs(&axes);
    build_token_store_for_inputs(doc, resolver_path, &inputs)
}
