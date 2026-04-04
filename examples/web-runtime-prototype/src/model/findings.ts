import cssDiagnostics from "../../generated/paint/css/diagnostics.pack.json";
import webDiagnostics from "../../generated/paint/web/diagnostics.pack.json";

type DiagnosticsRecord = {
  witnessId: string;
  kind: string;
  familyId: string;
  familyLabel: string;
  severity: "error" | "warn" | "info";
  summary: string;
  nextAction: string;
  tokenPath?: string;
  context?: string;
  filePath?: string;
  jsonPointer?: string;
  pack?: string;
};

type DiagnosticsProjection = {
  reportKind: string;
  sourceReport: {
    file: string;
  };
  summary: {
    total: number;
    clean: boolean;
    families: Array<{
      familyId: string;
      familyLabel: string;
      count: number;
    }>;
    severities: Array<{
      severity: string;
      count: number;
    }>;
  };
  backendArtifacts?: Array<{
    backendId: string;
  }>;
  records: DiagnosticsRecord[];
};

export type FindingViewModel = {
  family: string;
  familyId: string;
  kind: string;
  message: string;
  location: string | null;
  nextAction: string;
  severity: string;
  witnessId: string;
};

export type ValidationReportViewModel = {
  artifact: string;
  backendId: string;
  findings: FindingViewModel[];
  reportKind: string;
  total: number;
};

export type ValidationSummaryModel = {
  byFamily: Array<{ count: number; family: string; familyId: string }>;
  bySeverity: Array<{ count: number; severity: string }>;
  isClean: boolean;
  reports: ValidationReportViewModel[];
  total: number;
};

function locationSummary(finding: DiagnosticsRecord) {
  const fragments = [
    finding.tokenPath,
    finding.context ? `at ${finding.context}` : null,
    finding.filePath,
    finding.jsonPointer,
  ].filter((fragment): fragment is string => Boolean(fragment));

  return fragments.length > 0 ? fragments.join(" · ") : null;
}

function findingViewModels(findings: DiagnosticsRecord[]): FindingViewModel[] {
  return findings.map((finding) => ({
    family: finding.familyLabel,
    familyId: finding.familyId,
    kind: finding.kind,
    message: finding.summary,
    location: locationSummary(finding),
    nextAction: finding.nextAction,
    severity: finding.severity,
    witnessId: finding.witnessId,
  }));
}

const reportSources = [
  {
    artifact: "generated/paint/css/diagnostics.pack.json",
    backendId:
      (cssDiagnostics as DiagnosticsProjection).backendArtifacts?.[0]?.backendId ?? "unknown",
    report: cssDiagnostics as DiagnosticsProjection,
  },
  {
    artifact: "generated/paint/web/diagnostics.pack.json",
    backendId:
      (webDiagnostics as DiagnosticsProjection).backendArtifacts?.[0]?.backendId ?? "unknown",
    report: webDiagnostics as DiagnosticsProjection,
  },
];

function aggregateFamilySummary() {
  const counts = new Map<string, { family: string; count: number }>();
  for (const source of reportSources) {
    for (const family of source.report.summary.families) {
      const entry = counts.get(family.familyId);
      if (entry) {
        entry.count += family.count;
      } else {
        counts.set(family.familyId, {
          family: family.familyLabel,
          count: family.count,
        });
      }
    }
  }

  return [...counts.entries()]
    .map(([familyId, value]) => ({
      count: value.count,
      family: value.family,
      familyId,
    }))
    .sort((left, right) => right.count - left.count || left.family.localeCompare(right.family));
}

function aggregateSeveritySummary() {
  const counts = new Map<string, number>();
  for (const source of reportSources) {
    for (const severity of source.report.summary.severities) {
      counts.set(severity.severity, (counts.get(severity.severity) ?? 0) + severity.count);
    }
  }

  return [...counts.entries()]
    .map(([severity, count]) => ({ count, severity }))
    .sort((left, right) => {
      const rank = (value: string) =>
        value === "error" ? 0 : value === "warn" ? 1 : value === "info" ? 2 : 3;
      return rank(left.severity) - rank(right.severity) || left.severity.localeCompare(right.severity);
    });
}

export function buildValidationSummaryModel(): ValidationSummaryModel {
  const reports = reportSources.map((source) => ({
    artifact: source.artifact,
    backendId: source.backendId,
    findings: findingViewModels(source.report.records),
    reportKind: source.report.reportKind,
    total: source.report.summary.total,
  }));

  return {
    byFamily: aggregateFamilySummary(),
    bySeverity: aggregateSeveritySummary(),
    isClean: reports.every((report) => report.total === 0),
    reports,
    total: reports.reduce((sum, report) => sum + report.total, 0),
  };
}
