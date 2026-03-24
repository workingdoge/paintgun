use std::path::{Component, Path, PathBuf};

pub fn validate_relative_path(raw: &str) -> Result<PathBuf, String> {
    if raw.trim().is_empty() {
        return Err("path is empty".to_string());
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err("absolute paths are not allowed".to_string());
    }
    for comp in path.components() {
        if matches!(comp, Component::RootDir | Component::Prefix(_)) {
            return Err("rooted paths are not allowed".to_string());
        }
    }
    Ok(path.to_path_buf())
}

pub fn resolve_existing_under(base_dir: &Path, raw: &str) -> Result<PathBuf, String> {
    resolve_existing_within(base_dir, raw, base_dir)
}

pub fn resolve_existing_within(
    base_dir: &Path,
    raw: &str,
    root_dir: &Path,
) -> Result<PathBuf, String> {
    let rel = validate_relative_path(raw)?;
    let base_abs = std::fs::canonicalize(base_dir).map_err(|e| {
        format!(
            "failed to canonicalize base directory {}: {e}",
            base_dir.display()
        )
    })?;
    let root_abs = std::fs::canonicalize(root_dir).map_err(|e| {
        format!(
            "failed to canonicalize root directory {}: {e}",
            root_dir.display()
        )
    })?;
    let joined = base_abs.join(rel);
    let target_abs = std::fs::canonicalize(&joined).map_err(|e| {
        let parent_in_root = joined
            .parent()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .map(|p| p.starts_with(&root_abs))
            .unwrap_or(false);
        if parent_in_root {
            format!("path is missing within trust root: {}", raw)
        } else {
            format!(
                "failed to canonicalize resolved path {}: {e}",
                joined.display()
            )
        }
    })?;
    if !target_abs.starts_with(&root_abs) {
        return Err(format!("path escapes trust root: {}", raw));
    }
    Ok(target_abs)
}
