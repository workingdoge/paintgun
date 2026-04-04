use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFingerprint {
    pub file: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutableFingerprint {
    pub version: String,
    pub size: u64,
    pub modified_unix_ms: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageCacheRecord {
    pub version: u32,
    pub stage: String,
    pub key: String,
    pub fingerprint: serde_json::Value,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageCacheStatus {
    Hit,
    Miss(StageCacheMissReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageCacheMissReason {
    MetadataMissing,
    MetadataUnreadable,
    VersionMismatch,
    KeyChanged,
    MissingOutput(String),
}

pub const STAGE_CACHE_VERSION: u32 = 1;

pub fn current_executable_fingerprint() -> Result<ExecutableFingerprint, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to resolve current executable: {e}"))?;
    let metadata = fs::metadata(&exe)
        .map_err(|e| format!("failed to stat current executable {}: {e}", exe.display()))?;
    let modified = metadata
        .modified()
        .map_err(|e| format!("failed to read executable mtime {}: {e}", exe.display()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            format!(
                "failed to normalize executable mtime {}: {e}",
                exe.display()
            )
        })?
        .as_millis();
    Ok(ExecutableFingerprint {
        version: env!("CARGO_PKG_VERSION").to_string(),
        size: metadata.len(),
        modified_unix_ms: modified,
    })
}

pub fn fingerprint_file(path: &Path) -> Result<FileFingerprint, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(FileFingerprint {
        file: path.display().to_string(),
        sha256: format!("sha256:{}", crate::util::sha256_hex(&bytes)),
        size: bytes.len() as u64,
    })
}

pub fn stage_cache_file(out_dir: &Path, stage: &str) -> PathBuf {
    out_dir
        .join(".paint")
        .join("cache")
        .join(format!("{stage}.json"))
}

pub fn stable_cache_key(value: &impl Serialize) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| format!("failed to serialize cache key: {e}"))?;
    Ok(format!("sha256:{}", crate::util::sha256_hex(&bytes)))
}

pub fn check_stage_cache(
    out_dir: &Path,
    stage: &str,
    fingerprint: &impl Serialize,
    expected_outputs: &[PathBuf],
) -> Result<StageCacheStatus, String> {
    let cache_path = stage_cache_file(out_dir, stage);
    if !cache_path.exists() {
        return Ok(StageCacheStatus::Miss(
            StageCacheMissReason::MetadataMissing,
        ));
    }

    let bytes = match fs::read(&cache_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(StageCacheStatus::Miss(
                StageCacheMissReason::MetadataUnreadable,
            ))
        }
    };
    let record: StageCacheRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(_) => {
            return Ok(StageCacheStatus::Miss(
                StageCacheMissReason::MetadataUnreadable,
            ))
        }
    };
    let key = stable_cache_key(fingerprint)?;

    if record.version != STAGE_CACHE_VERSION || record.stage != stage {
        return Ok(StageCacheStatus::Miss(
            StageCacheMissReason::VersionMismatch,
        ));
    }
    if record.key != key {
        return Ok(StageCacheStatus::Miss(StageCacheMissReason::KeyChanged));
    }

    for output in expected_outputs {
        let full_path = out_dir.join(output);
        if !full_path.exists() {
            return Ok(StageCacheStatus::Miss(StageCacheMissReason::MissingOutput(
                output.display().to_string(),
            )));
        }
    }

    Ok(StageCacheStatus::Hit)
}

pub fn write_stage_cache(
    out_dir: &Path,
    stage: &str,
    fingerprint: &impl Serialize,
    outputs: &[PathBuf],
) -> Result<(), String> {
    let cache_path = stage_cache_file(out_dir, stage);
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    let record = StageCacheRecord {
        version: STAGE_CACHE_VERSION,
        stage: stage.to_string(),
        key: stable_cache_key(fingerprint)?,
        fingerprint: serde_json::to_value(fingerprint)
            .map_err(|e| format!("failed to serialize cache fingerprint: {e}"))?,
        outputs: outputs
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&record)
        .map_err(|e| format!("failed to serialize {}: {e}", cache_path.display()))?;
    fs::write(&cache_path, bytes)
        .map_err(|e| format!("failed to write {}: {e}", cache_path.display()))
}
