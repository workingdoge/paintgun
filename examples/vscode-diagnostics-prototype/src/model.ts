export type DiagnosticsRecord = {
  recordId: string;
  witnessId: string;
  kind: string;
  familyId: string;
  familyLabel: string;
  severity: "error" | "warn" | "info" | string;
  fixability: string;
  summary: string;
  meaning: string;
  nextAction: string;
  tokenPath?: string;
  context?: string;
  filePath?: string;
  jsonPointer?: string;
  pack?: string;
};

export type DiagnosticsProjection = {
  projectionVersion: number;
  projectionKind: string;
  reportKind: "pack" | "compose" | string;
  sourceReport: {
    file: string;
  };
  summary: {
    total: number;
    clean: boolean;
  };
  records: DiagnosticsRecord[];
};

export type DiagnosticsFindingModel = {
  filePath?: string;
  id: string;
  jsonPointer?: string;
  label: string;
  nextAction: string;
  severity: string;
  summary: string;
  tooltip: string;
};

export type DiagnosticsDocumentModel = {
  description: string;
  findings: DiagnosticsFindingModel[];
  label: string;
  relativePath: string;
  reportKind: string;
};

function severityRank(severity: string) {
  return severity === "error" ? 0 : severity === "warn" ? 1 : severity === "info" ? 2 : 3;
}

function locationParts(record: DiagnosticsRecord) {
  return [record.filePath, record.jsonPointer].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
}

function recordTooltip(record: DiagnosticsRecord) {
  const lines = [
    `${record.familyLabel} (${record.severity})`,
    record.summary,
    `Next action: ${record.nextAction}`,
  ];

  const location = locationParts(record).join(" ");
  if (location.length > 0) {
    lines.push(`Location: ${location}`);
  }

  lines.push(`Witness: ${record.witnessId}`);
  return lines.join("\n");
}

export function buildDiagnosticsDocumentModel(
  relativePath: string,
  projection: DiagnosticsProjection,
): DiagnosticsDocumentModel {
  const findings = [...projection.records]
    .sort((left, right) => {
      return (
        severityRank(left.severity) - severityRank(right.severity) ||
        left.familyLabel.localeCompare(right.familyLabel) ||
        left.witnessId.localeCompare(right.witnessId)
      );
    })
    .map((record) => ({
      filePath: record.filePath,
      id: record.recordId,
      jsonPointer: record.jsonPointer,
      label: record.familyLabel,
      nextAction: record.nextAction,
      severity: record.severity,
      summary: record.summary,
      tooltip: recordTooltip(record),
    }));

  return {
    description: `${projection.reportKind} · ${projection.summary.total} finding(s)`,
    findings,
    label: relativePath,
    relativePath,
    reportKind: projection.reportKind,
  };
}
