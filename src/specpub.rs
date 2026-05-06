use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cert::{ManifestEntry, ToolInfo};
use crate::path_safety::{resolve_existing_under, resolve_existing_within, validate_relative_path};
use crate::util::sha256_hex;

pub const SPEC_PUBLICATION_SCHEMA: &str = "atlas.spec-publication.v1";
pub const SPEC_PACK_SCHEMA: &str = "paintgun.spec-pack.v1";
pub const SPEC_INDEX_SCHEMA: &str = "paintgun.spec-index.v1";
pub const ATLAS_SPEC_PUBLICATION_SCHEMA_JSON: &str =
    include_str!("../schemas/atlas/atlas-spec-publication.v1.schema.json");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecPublicationManifest {
    pub schema: String,
    pub site: String,
    pub source_root: String,
    pub series: Vec<SpecSeriesDeclaration>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecSeriesDeclaration {
    pub id: String,
    pub title: String,
    pub documents: Vec<SpecDocumentDeclaration>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecDocumentDeclaration {
    pub id: String,
    pub title: String,
    pub status: String,
    pub category: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecPackManifest {
    pub schema: String,
    pub publication_schema: String,
    pub site: String,
    pub source_root: String,
    pub generated_by: ToolInfo,
    pub input_manifest: ManifestEntry,
    pub index: ManifestEntry,
    pub documents: Vec<SpecPackedDocument>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecPackedDocument {
    pub series_id: String,
    pub id: String,
    pub title: String,
    pub status: String,
    pub category: String,
    pub source_path: String,
    pub pack_path: ManifestEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecIndex {
    pub schema: String,
    pub site: String,
    pub series: Vec<SpecIndexSeries>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecIndexSeries {
    pub id: String,
    pub title: String,
    pub documents: Vec<SpecIndexDocument>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpecIndexDocument {
    pub id: String,
    pub title: String,
    pub status: String,
    pub category: String,
    pub source_path: String,
    pub pack_path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecPackBuildSummary {
    pub pack_manifest: String,
    pub index: String,
    pub documents: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecPackVerifyReport {
    pub ok: bool,
    pub manifest: String,
    pub checked_documents: usize,
    pub errors: Vec<String>,
}

pub fn build_spec_pack(
    manifest_path: &Path,
    out_dir: &Path,
    tool_version: &str,
) -> Result<SpecPackBuildSummary, String> {
    let manifest_bytes = fs::read(manifest_path).map_err(|e| {
        format!(
            "failed to read publication manifest {}: {e}",
            manifest_path.display()
        )
    })?;
    let manifest: SpecPublicationManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| {
            format!(
                "failed to parse publication manifest {}: {e}",
                manifest_path.display()
            )
        })?;
    validate_publication_manifest(&manifest)?;

    fs::create_dir_all(out_dir).map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            out_dir.display()
        )
    })?;

    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let source_root = resolve_existing_within(manifest_dir, &manifest.source_root, manifest_dir)?;

    let input_dir = out_dir.join("inputs");
    let source_dir = out_dir.join("sources");
    fs::create_dir_all(&input_dir).map_err(|e| {
        format!(
            "failed to create input copy directory {}: {e}",
            input_dir.display()
        )
    })?;
    fs::create_dir_all(&source_dir).map_err(|e| {
        format!(
            "failed to create source copy directory {}: {e}",
            source_dir.display()
        )
    })?;

    let input_manifest_path = input_dir.join("spec-publication.json");
    fs::write(&input_manifest_path, &manifest_bytes).map_err(|e| {
        format!(
            "failed to write input manifest copy {}: {e}",
            input_manifest_path.display()
        )
    })?;

    let mut packed_docs = Vec::new();
    let mut index_series = Vec::new();

    for series in &manifest.series {
        let mut index_docs = Vec::new();
        let packed_series_dir = source_dir.join(safe_segment(&series.id)?);
        fs::create_dir_all(&packed_series_dir).map_err(|e| {
            format!(
                "failed to create packed series directory {}: {e}",
                packed_series_dir.display()
            )
        })?;

        for doc in &series.documents {
            let source_path = resolve_existing_under(&source_root, &doc.path)?;
            let extension = source_path
                .extension()
                .and_then(|s| s.to_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("md");
            let packed_path =
                packed_series_dir.join(format!("{}.{}", safe_segment(&doc.id)?, extension));
            fs::copy(&source_path, &packed_path).map_err(|e| {
                format!(
                    "failed to copy source document {} to {}: {e}",
                    source_path.display(),
                    packed_path.display()
                )
            })?;

            let entry = manifest_entry_for(&packed_path, out_dir)?;
            let packed = SpecPackedDocument {
                series_id: series.id.clone(),
                id: doc.id.clone(),
                title: doc.title.clone(),
                status: doc.status.clone(),
                category: doc.category.clone(),
                source_path: doc.path.clone(),
                pack_path: entry.clone(),
                order: doc.order,
                summary: doc.summary.clone(),
            };
            index_docs.push(SpecIndexDocument {
                id: doc.id.clone(),
                title: doc.title.clone(),
                status: doc.status.clone(),
                category: doc.category.clone(),
                source_path: doc.path.clone(),
                pack_path: entry.file.clone(),
                sha256: entry.sha256.clone(),
                size: entry.size,
                order: doc.order,
                summary: doc.summary.clone(),
            });
            packed_docs.push(packed);
        }

        index_series.push(SpecIndexSeries {
            id: series.id.clone(),
            title: series.title.clone(),
            documents: index_docs,
        });
    }

    let index = SpecIndex {
        schema: SPEC_INDEX_SCHEMA.to_string(),
        site: manifest.site.clone(),
        series: index_series,
    };
    let index_path = out_dir.join("spec.index.json");
    write_json(&index_path, &index)?;
    let index_entry = manifest_entry_for(&index_path, out_dir)?;

    let pack = SpecPackManifest {
        schema: SPEC_PACK_SCHEMA.to_string(),
        publication_schema: manifest.schema.clone(),
        site: manifest.site.clone(),
        source_root: manifest.source_root.clone(),
        generated_by: ToolInfo {
            name: "paintgun".to_string(),
            version: tool_version.to_string(),
        },
        input_manifest: manifest_entry_for(&input_manifest_path, out_dir)?,
        index: index_entry.clone(),
        documents: packed_docs,
    };
    let pack_path = out_dir.join("spec.pack.json");
    write_json(&pack_path, &pack)?;

    Ok(SpecPackBuildSummary {
        pack_manifest: display_slash(&pack_path),
        index: display_slash(&index_path),
        documents: pack.documents.len(),
    })
}

pub fn verify_spec_pack(pack_manifest_path: &Path) -> SpecPackVerifyReport {
    let mut report = SpecPackVerifyReport {
        ok: true,
        manifest: display_slash(pack_manifest_path),
        checked_documents: 0,
        errors: Vec::new(),
    };

    let base = pack_manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let bytes = match fs::read(pack_manifest_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            report.fail(format!(
                "failed to read spec pack manifest {}: {e}",
                pack_manifest_path.display()
            ));
            return report;
        }
    };
    let pack: SpecPackManifest = match serde_json::from_slice(&bytes) {
        Ok(pack) => pack,
        Err(e) => {
            report.fail(format!(
                "failed to parse spec pack manifest {}: {e}",
                pack_manifest_path.display()
            ));
            return report;
        }
    };

    if pack.schema != SPEC_PACK_SCHEMA {
        report.fail(format!(
            "spec pack schema mismatch: expected {}, got {}",
            SPEC_PACK_SCHEMA, pack.schema
        ));
    }
    if pack.publication_schema != SPEC_PUBLICATION_SCHEMA {
        report.fail(format!(
            "publication schema mismatch: expected {}, got {}",
            SPEC_PUBLICATION_SCHEMA, pack.publication_schema
        ));
    }

    check_entry(base, "inputManifest", &pack.input_manifest, &mut report);
    check_entry(base, "index", &pack.index, &mut report);
    for doc in &pack.documents {
        check_entry(
            base,
            &format!("document {}:{}", doc.series_id, doc.id),
            &doc.pack_path,
            &mut report,
        );
        report.checked_documents += 1;
    }

    match read_entry_json::<SpecIndex>(base, &pack.index) {
        Ok(index) => check_index_matches_pack(&index, &pack, &mut report),
        Err(e) => report.fail(e),
    }

    report
}

fn validate_publication_manifest(manifest: &SpecPublicationManifest) -> Result<(), String> {
    if manifest.schema != SPEC_PUBLICATION_SCHEMA {
        return Err(format!(
            "publication manifest schema mismatch: expected {}, got {}",
            SPEC_PUBLICATION_SCHEMA, manifest.schema
        ));
    }
    require_nonempty("site", &manifest.site)?;
    require_nonempty("sourceRoot", &manifest.source_root)?;
    validate_relative_path(&manifest.source_root)
        .map_err(|e| format!("invalid sourceRoot {}: {e}", manifest.source_root))?;
    if manifest.series.is_empty() {
        return Err("publication manifest must declare at least one series".to_string());
    }

    let mut series_ids = BTreeSet::new();
    let mut doc_ids = BTreeSet::new();
    for series in &manifest.series {
        require_nonempty("series.id", &series.id)?;
        require_nonempty("series.title", &series.title)?;
        safe_segment(&series.id)?;
        if !series_ids.insert(series.id.clone()) {
            return Err(format!("duplicate series id {}", series.id));
        }
        if series.documents.is_empty() {
            return Err(format!(
                "series {} must declare at least one document",
                series.id
            ));
        }
        for doc in &series.documents {
            require_nonempty("document.id", &doc.id)?;
            require_nonempty("document.title", &doc.title)?;
            require_nonempty("document.status", &doc.status)?;
            require_nonempty("document.category", &doc.category)?;
            require_nonempty("document.path", &doc.path)?;
            safe_segment(&doc.id)?;
            validate_relative_path(&doc.path)
                .map_err(|e| format!("invalid source path {}: {e}", doc.path))?;
            let key = format!("{}:{}", series.id, doc.id);
            if !doc_ids.insert(key.clone()) {
                return Err(format!("duplicate document id {}", key));
            }
        }
    }
    Ok(())
}

fn require_nonempty(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn safe_segment(raw: &str) -> Result<String, String> {
    require_nonempty("path segment", raw)?;
    if matches!(raw, "." | "..") {
        return Err(format!("path segment {raw:?} is not allowed"));
    }
    if raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        Ok(raw.to_string())
    } else {
        Err(format!(
            "path segment {raw:?} must use only ASCII alphanumeric, dash, underscore, or dot"
        ))
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| format!("failed to serialize {}: {e}", path.display()))?;
    fs::write(path, bytes).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn manifest_entry_for(path: &Path, base: &Path) -> Result<ManifestEntry, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let rel = path
        .strip_prefix(base)
        .map_err(|_| format!("{} is not under {}", path.display(), base.display()))?;
    Ok(ManifestEntry {
        file: path_to_slash(rel),
        sha256: format!("sha256:{}", sha256_hex(&bytes)),
        size: bytes.len() as u64,
    })
}

fn check_entry(base: &Path, label: &str, entry: &ManifestEntry, report: &mut SpecPackVerifyReport) {
    let path = match resolve_existing_under(base, &entry.file) {
        Ok(path) => path,
        Err(e) => {
            report.fail(format!(
                "[{label}] unsafe or missing path {}: {e}",
                entry.file
            ));
            return;
        }
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            report.fail(format!("[{label}] failed to read {}: {e}", path.display()));
            return;
        }
    };
    let sha256 = format!("sha256:{}", sha256_hex(&bytes));
    if sha256 != entry.sha256 || bytes.len() as u64 != entry.size {
        report.fail(format!(
            "[{label}] hash/size mismatch for {}: expected {} ({} bytes), got {} ({} bytes)",
            entry.file,
            entry.sha256,
            entry.size,
            sha256,
            bytes.len()
        ));
    }
}

fn read_entry_json<T: for<'de> Deserialize<'de>>(
    base: &Path,
    entry: &ManifestEntry,
) -> Result<T, String> {
    let path = resolve_existing_under(base, &entry.file)
        .map_err(|e| format!("[index] unsafe or missing path {}: {e}", entry.file))?;
    let bytes =
        fs::read(&path).map_err(|e| format!("[index] failed to read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("[index] failed to parse {}: {e}", path.display()))
}

fn check_index_matches_pack(
    index: &SpecIndex,
    pack: &SpecPackManifest,
    report: &mut SpecPackVerifyReport,
) {
    if index.schema != SPEC_INDEX_SCHEMA {
        report.fail(format!(
            "index schema mismatch: expected {}, got {}",
            SPEC_INDEX_SCHEMA, index.schema
        ));
    }
    if index.site != pack.site {
        report.fail(format!(
            "index site mismatch: expected {}, got {}",
            pack.site, index.site
        ));
    }

    let mut index_docs = BTreeMap::new();
    for series in &index.series {
        for doc in &series.documents {
            index_docs.insert(format!("{}:{}", series.id, doc.id), doc.clone());
        }
    }
    if index_docs.len() != pack.documents.len() {
        report.fail(format!(
            "index document count mismatch: expected {}, got {}",
            pack.documents.len(),
            index_docs.len()
        ));
    }

    for doc in &pack.documents {
        let key = format!("{}:{}", doc.series_id, doc.id);
        let Some(index_doc) = index_docs.get(&key) else {
            report.fail(format!("index missing document {key}"));
            continue;
        };
        if index_doc.pack_path != doc.pack_path.file
            || index_doc.sha256 != doc.pack_path.sha256
            || index_doc.size != doc.pack_path.size
            || index_doc.source_path != doc.source_path
            || index_doc.status != doc.status
            || index_doc.category != doc.category
        {
            report.fail(format!("index document {key} does not match pack manifest"));
        }
    }
}

fn path_to_slash(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn display_slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

impl SpecPackVerifyReport {
    fn fail(&mut self, error: impl Into<String>) {
        self.ok = false;
        self.errors.push(error.into());
    }
}
