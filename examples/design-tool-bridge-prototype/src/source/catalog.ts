import cssDiagnosticsJson from "../../../web-runtime-prototype/generated/paint/css/diagnostics.pack.json";
import { PAINTGUN_WEB_TOKENS_API_VERSION, contexts as tokenContexts } from "../../../web-runtime-prototype/generated/paint/web/tokens.ts";
import webDiagnosticsJson from "../../../web-runtime-prototype/generated/paint/web/diagnostics.pack.json";
import { systemCatalog } from "../../../web-runtime-prototype/src/generated/system-catalog.ts";

type DiagnosticsFamilyRollup = {
  familyId: string;
  familyLabel: string;
  count: number;
};

type DiagnosticsSeverityRollup = {
  severity: string;
  count: number;
};

export type DiagnosticsProjection = {
  projectionVersion: number;
  projectionKind: "editorDiagnostics";
  reportKind: "pack" | "compose";
  sourceReport: {
    file: string;
  };
  summary: {
    total: number;
    clean: boolean;
    families: DiagnosticsFamilyRollup[];
    severities: DiagnosticsSeverityRollup[];
  };
  backendArtifacts?: Array<{
    backendId: string;
    kind: string;
    file: string;
    sha256: string;
    size: number;
    apiVersion?: string;
  }>;
  records: Array<{
    recordId: string;
    witnessId: string;
    kind: string;
    familyId: string;
    familyLabel: string;
    severity: string;
    fixability: string;
    summary: string;
    meaning: string;
    nextAction: string;
    tokenPath?: string;
    context?: string;
    filePath?: string;
    jsonPointer?: string;
    pack?: string;
  }>;
};

export type TokenContext = (typeof tokenContexts)[number];

export const catalogBridgeSource = {
  systemCatalog,
  tokenApiVersion: PAINTGUN_WEB_TOKENS_API_VERSION,
  tokenContexts,
  diagnosticsBySourceId: {
    css: cssDiagnosticsJson as DiagnosticsProjection,
    web: webDiagnosticsJson as DiagnosticsProjection,
  },
} as const;
