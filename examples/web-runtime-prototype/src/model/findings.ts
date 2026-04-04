import cssValidation from "../../generated/paint/css/validation.json";
import webValidation from "../../generated/paint/web/validation.json";

type ValidationFinding = {
  witnessId: string;
  kind: string;
  severity: "error" | "warn" | "info";
  message: string;
  tokenPath?: string;
  context?: string;
  filePath?: string;
  jsonPointer?: string;
  pack?: string;
};

type ValidationReport = {
  reportKind: string;
  counts: {
    total: number;
    byKind: Record<string, number>;
  };
  findings: ValidationFinding[];
};

export type FindingViewModel = {
  family: string;
  kind: string;
  message: string;
  location: string | null;
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
  byKind: Array<{ count: number; kind: string }>;
  isClean: boolean;
  reports: ValidationReportViewModel[];
  total: number;
};

const FAMILY_BY_KIND: Record<string, string> = {
  bcViolation: "Boundary condition violation",
  composeConflict: "Compose conflict",
  conflict: "Conflicting definitions",
  gap: "Missing definition",
  inherited: "Inherited winner",
  locality_failure: "Locality failure",
  orthogonality: "Orthogonality issue",
  stability_failure: "Stability failure",
};

function familyForKind(kind: string) {
  return FAMILY_BY_KIND[kind] ?? kind;
}

function locationSummary(finding: ValidationFinding) {
  const fragments = [
    finding.tokenPath,
    finding.context ? `at ${finding.context}` : null,
    finding.filePath,
    finding.jsonPointer,
  ].filter((fragment): fragment is string => Boolean(fragment));

  return fragments.length > 0 ? fragments.join(" · ") : null;
}

function findingViewModels(findings: ValidationFinding[]): FindingViewModel[] {
  return findings.map((finding) => ({
    family: familyForKind(finding.kind),
    kind: finding.kind,
    message: finding.message,
    location: locationSummary(finding),
    severity: finding.severity,
    witnessId: finding.witnessId,
  }));
}

const reportSources = [
  {
    artifact: "generated/paint/css/validation.json",
    backendId: "web-css-vars",
    report: cssValidation as ValidationReport,
  },
  {
    artifact: "generated/paint/web/validation.json",
    backendId: "web-tokens-ts",
    report: webValidation as ValidationReport,
  },
];

export function buildValidationSummaryModel(): ValidationSummaryModel {
  const reports = reportSources.map((source) => ({
    artifact: source.artifact,
    backendId: source.backendId,
    findings: findingViewModels(source.report.findings),
    reportKind: source.report.reportKind,
    total: source.report.counts.total,
  }));

  const byKind = Object.entries(cssValidation.counts.byKind)
    .filter(([, count]) => count > 0)
    .map(([kind, count]) => ({ count, kind }))
    .sort((left, right) => right.count - left.count || left.kind.localeCompare(right.kind));

  return {
    byKind,
    isClean: cssValidation.counts.total === 0,
    reports,
    total: cssValidation.counts.total,
  };
}
