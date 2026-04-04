use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cert::BackendArtifactDescriptor;
use crate::finding_presentation::{presentation_for_kind, FindingPresentation};

const DIAGNOSTICS_PROJECTION_VERSION: u32 = 1;
const DIAGNOSTICS_PROJECTION_KIND: &str = "editorDiagnostics";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSourceReport {
    pub file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsFamilySummary {
    #[serde(rename = "familyId")]
    pub family_id: String,
    #[serde(rename = "familyLabel")]
    pub family_label: String,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSeveritySummary {
    pub severity: String,
    pub count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSummary {
    pub total: usize,
    pub clean: bool,
    pub families: Vec<DiagnosticsFamilySummary>,
    pub severities: Vec<DiagnosticsSeveritySummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsRecord {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "witnessId")]
    pub witness_id: String,
    pub kind: String,
    #[serde(rename = "familyId")]
    pub family_id: String,
    #[serde(rename = "familyLabel")]
    pub family_label: String,
    pub severity: String,
    pub fixability: String,
    pub summary: String,
    pub meaning: String,
    #[serde(rename = "nextAction")]
    pub next_action: String,
    #[serde(rename = "tokenPath", skip_serializing_if = "Option::is_none")]
    pub token_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(rename = "jsonPointer", skip_serializing_if = "Option::is_none")]
    pub json_pointer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditorDiagnosticsProjection {
    #[serde(rename = "projectionVersion")]
    pub projection_version: u32,
    #[serde(rename = "projectionKind")]
    pub projection_kind: String,
    #[serde(rename = "reportKind")]
    pub report_kind: String,
    #[serde(rename = "sourceReport")]
    pub source_report: DiagnosticsSourceReport,
    pub summary: DiagnosticsSummary,
    #[serde(
        rename = "backendArtifacts",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub backend_artifacts: Vec<BackendArtifactDescriptor>,
    pub records: Vec<DiagnosticsRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct SourceDiagnosticsReport {
    #[serde(rename = "reportKind")]
    report_kind: String,
    #[serde(rename = "backendArtifacts", default)]
    backend_artifacts: Vec<BackendArtifactDescriptor>,
    #[serde(default)]
    findings: Vec<SourceDiagnosticsFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct SourceDiagnosticsFinding {
    #[serde(rename = "witnessId")]
    witness_id: String,
    kind: String,
    severity: String,
    message: String,
    #[serde(rename = "tokenPath")]
    token_path: Option<String>,
    context: Option<String>,
    #[serde(rename = "filePath")]
    file_path: Option<String>,
    #[serde(rename = "jsonPointer")]
    json_pointer: Option<String>,
    pack: Option<String>,
}

pub fn build_editor_diagnostics_projection(
    report_json: &Value,
    source_report_file: &str,
) -> Result<EditorDiagnosticsProjection, String> {
    let report: SourceDiagnosticsReport = serde_json::from_value(report_json.clone())
        .map_err(|e| format!("failed to parse source report for diagnostics projection: {e}"))?;

    let records = report
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| build_record(&report.report_kind, index, finding))
        .collect::<Vec<_>>();

    Ok(EditorDiagnosticsProjection {
        projection_version: DIAGNOSTICS_PROJECTION_VERSION,
        projection_kind: DIAGNOSTICS_PROJECTION_KIND.to_string(),
        report_kind: report.report_kind,
        source_report: DiagnosticsSourceReport {
            file: source_report_file.to_string(),
        },
        summary: build_summary(&records),
        backend_artifacts: report.backend_artifacts,
        records,
    })
}

pub fn build_editor_diagnostics_projection_json(
    report_json: &Value,
    source_report_file: &str,
) -> Result<Value, String> {
    let projection = build_editor_diagnostics_projection(report_json, source_report_file)?;
    serde_json::to_value(projection)
        .map_err(|e| format!("failed to serialize diagnostics projection: {e}"))
}

fn build_record(
    report_kind: &str,
    index: usize,
    finding: &SourceDiagnosticsFinding,
) -> DiagnosticsRecord {
    let presentation = normalized_presentation(&finding.kind);
    DiagnosticsRecord {
        record_id: format!("{report_kind}:{}:{index}", finding.witness_id),
        witness_id: finding.witness_id.clone(),
        kind: finding.kind.clone(),
        family_id: presentation.family_id.to_string(),
        family_label: presentation.family_label.to_string(),
        severity: finding.severity.clone(),
        fixability: presentation.fixability.to_string(),
        summary: finding.message.clone(),
        meaning: presentation.meaning.to_string(),
        next_action: presentation.next_action.to_string(),
        token_path: finding.token_path.clone(),
        context: finding.context.clone(),
        file_path: finding.file_path.clone(),
        json_pointer: finding.json_pointer.clone(),
        pack: finding.pack.clone(),
    }
}

fn build_summary(records: &[DiagnosticsRecord]) -> DiagnosticsSummary {
    let mut family_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut severity_counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in records {
        *family_counts
            .entry((record.family_id.clone(), record.family_label.clone()))
            .or_insert(0) += 1;
        *severity_counts.entry(record.severity.clone()).or_insert(0) += 1;
    }

    let mut families = family_counts
        .into_iter()
        .map(
            |((family_id, family_label), count)| DiagnosticsFamilySummary {
                family_id,
                family_label,
                count,
            },
        )
        .collect::<Vec<_>>();
    families.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then(left.family_label.cmp(&right.family_label))
    });

    let mut severities = severity_counts
        .into_iter()
        .map(|(severity, count)| DiagnosticsSeveritySummary { severity, count })
        .collect::<Vec<_>>();
    severities.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then(left.severity.cmp(&right.severity))
    });

    DiagnosticsSummary {
        total: records.len(),
        clean: records.is_empty(),
        families,
        severities,
    }
}

fn severity_rank(severity: &str) -> usize {
    match severity {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        _ => 3,
    }
}

fn normalized_presentation(kind: &str) -> FindingPresentation {
    match kind {
        "locality_failure" => FindingPresentation {
            family_id: "constraint-failure",
            family_label: "Constraint failure",
            technical_kind: "locality_failure",
            severity: "error",
            fixability: "guided",
            meaning:
                "The authored system violates a required restriction or supporting-definition rule.",
            next_action:
                "Add the required supporting definition or repair the restriction that this context depends on.",
        },
        "stability_failure" => FindingPresentation {
            family_id: "order-dependent-resolution",
            family_label: "Order-dependent resolution",
            technical_kind: "stability_failure",
            severity: "error",
            fixability: "guided",
            meaning: "The resolved result changes depending on evaluation or composition order.",
            next_action:
                "Normalize the authoring so the same result is produced regardless of traversal or composition order.",
        },
        _ => presentation_for_kind(kind).unwrap_or(FindingPresentation {
            family_id: "unclassified-finding",
            family_label: "Unclassified finding",
            technical_kind: "unknown",
            severity: "warn",
            fixability: "review",
            meaning: "Paint emitted a finding kind that this projection does not classify yet.",
            next_action: "Inspect the finding summary and underlying witness details before editing the source.",
        }),
    }
}
