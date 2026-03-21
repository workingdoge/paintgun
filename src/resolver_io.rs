use std::fs;
use std::path::{Path, PathBuf};

use tbp_resolver_kernel::{FlattenError, LoadFileError};
use tbp_resolver_model::{Input, ResolverDoc, ResolverSource};

use crate::dtcg::JValue;

pub trait ResolverIo {
    fn resolve_existing_under(&self, base_dir: &Path, rel: &str) -> Result<PathBuf, String>;
    fn read_json_value(&self, path: &Path) -> Result<JValue, LoadFileError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FsResolverIo;

impl ResolverIo for FsResolverIo {
    fn resolve_existing_under(&self, base_dir: &Path, rel: &str) -> Result<PathBuf, String> {
        crate::path_safety::resolve_existing_under(base_dir, rel)
    }

    fn read_json_value(&self, path: &Path) -> Result<JValue, LoadFileError> {
        let bytes = fs::read(path).map_err(|e| LoadFileError::ReadFile {
            path: path.display().to_string(),
            cause: e.to_string(),
        })?;

        serde_json::from_slice(&bytes).map_err(|e| LoadFileError::ParseJson {
            path: path.display().to_string(),
            cause: e.to_string(),
        })
    }
}

pub fn load_source_with_io(
    io: &impl ResolverIo,
    doc: &ResolverDoc,
    source: &ResolverSource,
    base_dir: &Path,
) -> Result<JValue, FlattenError> {
    tbp_resolver_kernel::load_source(
        doc,
        source,
        base_dir,
        &|b, r| io.resolve_existing_under(b, r),
        &|p| io.read_json_value(p),
    )
}

pub fn flatten_with_io(
    io: &impl ResolverIo,
    doc: &ResolverDoc,
    input: &Input,
    base_dir: &Path,
) -> Result<JValue, FlattenError> {
    tbp_resolver_kernel::flatten(
        doc,
        input,
        base_dir,
        &|b, r| io.resolve_existing_under(b, r),
        &|p| io.read_json_value(p),
    )
}

pub fn axes_relevant_to_tokens_with_io(
    io: &impl ResolverIo,
    doc: &ResolverDoc,
    base_dir: &Path,
    token_paths: &std::collections::BTreeSet<String>,
) -> Result<std::collections::BTreeSet<String>, FlattenError> {
    tbp_resolver_kernel::axes_relevant_to_tokens(
        doc,
        base_dir,
        token_paths,
        &|b, r| io.resolve_existing_under(b, r),
        &|p| io.read_json_value(p),
    )
}
