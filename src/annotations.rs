use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ids::{TokenPathId, WitnessId};

#[derive(Clone, Debug, Deserialize)]
pub struct ReportCounts {
    pub total: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReportFinding {
    #[serde(rename = "witnessId")]
    pub witness_id: WitnessId,
    pub kind: String,
    pub severity: String,
    pub message: String,
    #[serde(rename = "tokenPath")]
    pub token_path: Option<TokenPathId>,
    pub context: Option<String>,
    #[serde(rename = "filePath")]
    pub file_path: Option<String>,
    #[serde(rename = "jsonPointer")]
    pub json_pointer: Option<String>,
    pub pack: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DiagnosticReport {
    #[serde(rename = "reportVersion")]
    pub report_version: u32,
    #[serde(rename = "reportKind")]
    pub report_kind: String,
    #[serde(rename = "conflictMode")]
    pub conflict_mode: String,
    pub counts: ReportCounts,
    pub findings: Vec<ReportFinding>,
}

#[derive(Clone, Debug)]
pub struct AnnotationOutput {
    pub lines: Vec<String>,
    pub emitted: usize,
    pub truncated: usize,
}

pub fn read_report(path: &Path) -> Result<DiagnosticReport, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_slice::<DiagnosticReport>(&bytes)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn escape_data(v: &str) -> String {
    v.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_prop(v: &str) -> String {
    escape_data(v).replace(':', "%3A").replace(',', "%2C")
}

fn severity_command(severity: &str) -> &'static str {
    match severity {
        "error" => "error",
        "warn" => "warning",
        _ => "notice",
    }
}

fn normalize_annotation_file(file_root: &Path, file_path: &str) -> String {
    let in_path = PathBuf::from(file_path);
    let joined = if in_path.is_absolute() {
        in_path
    } else {
        file_root.join(in_path)
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Ok(rel) = joined.strip_prefix(&cwd) {
        return rel.to_string_lossy().replace('\\', "/");
    }
    joined.to_string_lossy().replace('\\', "/")
}

pub fn build_github_annotations(
    report: &DiagnosticReport,
    file_root: &Path,
    max_annotations: usize,
) -> AnnotationOutput {
    let mut lines = Vec::new();
    let mut emitted = 0usize;
    let mut truncated = 0usize;

    for f in &report.findings {
        if emitted >= max_annotations {
            truncated += 1;
            continue;
        }

        let command = severity_command(&f.severity);
        let title = format!("tbp/{} {}", f.kind, f.witness_id);
        let mut msg = f.message.clone();
        if let Some(tp) = &f.token_path {
            msg.push_str(&format!(" | tokenPath={tp}"));
        }
        if let Some(ctx) = &f.context {
            msg.push_str(&format!(" | context={ctx}"));
        }
        if let Some(ptr) = &f.json_pointer {
            msg.push_str(&format!(" | jsonPointer={ptr}"));
        }
        if let Some(pack) = &f.pack {
            msg.push_str(&format!(" | pack={pack}"));
        }

        let line = if let Some(fp) = &f.file_path {
            let resolved = normalize_annotation_file(file_root, fp);
            format!(
                "::{} file={},line=1,title={}::{}",
                command,
                escape_prop(&resolved),
                escape_prop(&title),
                escape_data(&msg)
            )
        } else {
            format!(
                "::{} title={}::{}",
                command,
                escape_prop(&title),
                escape_data(&msg)
            )
        };
        lines.push(line);
        emitted += 1;
    }

    AnnotationOutput {
        lines,
        emitted,
        truncated,
    }
}
