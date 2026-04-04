import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, normalize, resolve } from "node:path";

type ArtifactDescriptor = {
  backendId: string;
  kind: string;
  file: string;
  sha256: string;
  size: number;
  apiVersion?: string;
};

type DiagnosticsProjection = {
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
  reportKind: string;
  sourceReport: {
    file: string;
  };
  backendArtifacts?: Array<{
    backendId: string;
  }>;
};

type Manifest = {
  tool: {
    name: string;
    version: string;
  };
  spec: string;
  packIdentity: {
    packId: string;
    packVersion: string;
    contentHash: string;
  };
  backendArtifacts: ArtifactDescriptor[];
};

type SystemInput = {
  name: string;
  label: string;
  description: string;
  kind: string;
  default: string | boolean;
  options?: string[];
};

type SystemExample = {
  id: string;
  label: string;
  context: string;
  inputs: Record<string, string | boolean>;
  content: Record<string, string>;
};

type SystemSchema = {
  schemaVersion: string;
  system: {
    id: string;
    title: string;
    release: string;
  };
  components: Array<{
    id: string;
    title: string;
    description: string;
    status: string;
    compatibility: Record<string, string | number | boolean>;
    accessibility: {
      role: string;
      notes: string[];
    };
    surfaces: {
      parts: Array<{ name: string; description: string }>;
      slots: Array<{ name: string; description: string }>;
    };
    inputs: SystemInput[];
    examples: SystemExample[];
  }>;
};

type CatalogVerificationSummary = {
  scope: "system" | "system-wide";
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
  reports: Array<{
    sourceId: string;
    file: string;
    reportKind: string;
    backendIds: string[];
    total: number;
    clean: boolean;
  }>;
};

const exampleRoot = resolve(import.meta.dir, "..");
const schemaPath = join(exampleRoot, "system.schema.json");
const paintGeneratedRoot = join(exampleRoot, "generated", "paint");
const outputPath = join(exampleRoot, "generated", "system.catalog.json");
const catalogVersion = "paint.catalog.ir.alpha1";

function fromExampleRoot(path: string) {
  return normalize(path).replace(/\\/g, "/");
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

function sortByLabelThenId<T extends { title?: string; id?: string }>(left: T, right: T) {
  return (left.title ?? left.id ?? "").localeCompare(right.title ?? right.id ?? "");
}

async function loadPaintSources() {
  const entries = await readdir(paintGeneratedRoot, { withFileTypes: true });
  const sources = await Promise.all(
    entries
      .filter((entry) => entry.isDirectory())
      .map(async (entry) => {
        const sourceId = entry.name;
        const sourceRoot = join(paintGeneratedRoot, entry.name);
        const manifestPath = join(sourceRoot, "ctc.manifest.json");
        const diagnosticsPath = join(sourceRoot, "diagnostics.pack.json");
        const manifest = await readJson<Manifest>(manifestPath);
        const diagnostics = await readJson<DiagnosticsProjection>(diagnosticsPath);
        return {
          sourceId,
          manifestPath,
          diagnosticsPath,
          manifest,
          diagnostics,
        };
      }),
  );

  return sources.sort((left, right) => left.sourceId.localeCompare(right.sourceId));
}

function artifactReferencesForSources(
  sources: Awaited<ReturnType<typeof loadPaintSources>>,
) {
  return sources.flatMap((source) =>
    source.manifest.backendArtifacts.map((artifact) => ({
      sourceId: source.sourceId,
      backendId: artifact.backendId,
      kind: artifact.kind,
      file: fromExampleRoot(resolve(dirname(source.manifestPath), artifact.file).slice(exampleRoot.length + 1)),
      sha256: artifact.sha256,
      size: artifact.size,
      ...(artifact.apiVersion ? { apiVersion: artifact.apiVersion } : {}),
    })),
  );
}

function verificationSummaryForSources(
  sources: Awaited<ReturnType<typeof loadPaintSources>>,
  scope: "system" | "system-wide",
): CatalogVerificationSummary {
  const familyCounts = new Map<string, { familyLabel: string; count: number }>();
  const severityCounts = new Map<string, number>();

  for (const source of sources) {
    for (const family of source.diagnostics.summary.families) {
      const current = familyCounts.get(family.familyId);
      if (current) {
        current.count += family.count;
      } else {
        familyCounts.set(family.familyId, {
          familyLabel: family.familyLabel,
          count: family.count,
        });
      }
    }
    for (const severity of source.diagnostics.summary.severities) {
      severityCounts.set(
        severity.severity,
        (severityCounts.get(severity.severity) ?? 0) + severity.count,
      );
    }
  }

  return {
    scope,
    total: sources.reduce((sum, source) => sum + source.diagnostics.summary.total, 0),
    clean: sources.every((source) => source.diagnostics.summary.clean),
    families: [...familyCounts.entries()]
      .map(([familyId, entry]) => ({
        familyId,
        familyLabel: entry.familyLabel,
        count: entry.count,
      }))
      .sort((left, right) => right.count - left.count || left.familyLabel.localeCompare(right.familyLabel)),
    severities: [...severityCounts.entries()]
      .map(([severity, count]) => ({ severity, count }))
      .sort((left, right) => left.severity.localeCompare(right.severity)),
    reports: sources.map((source) => ({
      sourceId: source.sourceId,
      file: fromExampleRoot(source.diagnosticsPath.slice(exampleRoot.length + 1)),
      reportKind: source.diagnostics.reportKind,
      backendIds: [...new Set((source.diagnostics.backendArtifacts ?? []).map((artifact) => artifact.backendId))],
      total: source.diagnostics.summary.total,
      clean: source.diagnostics.summary.clean,
    })),
  };
}

const schema = await readJson<SystemSchema>(schemaPath);
const sources = await loadPaintSources();
const artifactReferences = artifactReferencesForSources(sources);
const systemVerificationSummary = verificationSummaryForSources(sources, "system");

const catalog = {
  catalogSystem: {
    id: schema.system.id,
    title: schema.system.title,
    release: schema.system.release,
    schemaVersion: schema.schemaVersion,
    catalogVersion,
    paintSources: sources.map((source) => ({
      id: source.sourceId,
      manifest: fromExampleRoot(source.manifestPath.slice(exampleRoot.length + 1)),
      diagnostics: fromExampleRoot(source.diagnosticsPath.slice(exampleRoot.length + 1)),
      tool: source.manifest.tool,
      spec: source.manifest.spec,
      packIdentity: source.manifest.packIdentity,
    })),
    artifactReferences,
    verificationSummary: systemVerificationSummary,
  },
  catalogComponents: [...schema.components]
    .sort(sortByLabelThenId)
    .map((component) => ({
      id: component.id,
      title: component.title,
      description: component.description,
      status: component.status,
      compatibility: component.compatibility,
      accessibility: component.accessibility,
      parts: component.surfaces.parts,
      slots: component.surfaces.slots,
      inputs: component.inputs,
      examples: component.examples,
      tokenRoleBindings: [],
      artifactScope: "system-wide",
      artifactReferences,
      verificationSummary: verificationSummaryForSources(sources, "system-wide"),
    })),
};

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(catalog, null, 2)}\n`, "utf8");
console.log(`wrote ${outputPath}`);
