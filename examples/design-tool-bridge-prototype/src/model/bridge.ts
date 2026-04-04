import { catalogBridgeSource, type DiagnosticsProjection, type TokenContext } from "../source/catalog.ts";

type ArtifactReference = (typeof catalogBridgeSource.systemCatalog.catalogSystem.artifactReferences)[number];
type CatalogComponent = (typeof catalogBridgeSource.systemCatalog.catalogComponents)[number];
type VerificationReport = (typeof catalogBridgeSource.systemCatalog.catalogSystem.verificationSummary.reports)[number];

export type BridgeMetric = {
  label: string;
  value: string;
};

export type BridgeSourceCard = {
  id: string;
  label: string;
  manifest: string;
  diagnostics: string;
  spec: string;
  toolVersion: string;
  pack: string;
  packHash: string;
  artifactCount: number;
  findingCount: number;
  clean: boolean;
};

export type BridgeExamplePreview = {
  label: string;
  context: string;
  inputs: string[];
  contentLabel: string;
  tokenPreview: Array<{
    label: string;
    value: string;
    swatch?: string;
  }>;
};

export type BridgeArtifactGroup = {
  backendId: string;
  artifacts: Array<{
    kind: string;
    file: string;
    size: string;
    apiVersion?: string;
  }>;
};

export type BridgeVerificationReport = {
  sourceId: string;
  reportFile: string;
  backendIds: string[];
  findingCount: number;
  clean: boolean;
  families: string[];
  sourceReportFile: string;
};

export type BridgeComponentListItem = {
  id: string;
  title: string;
  status: string;
  description: string;
  exampleCount: number;
  inputCount: number;
  findingCount: number;
  clean: boolean;
};

export type BridgeComponentDetail = {
  id: string;
  title: string;
  status: string;
  description: string;
  compatibilityLabel: string;
  accessibilityNotes: string[];
  parts: string[];
  slots: string[];
  inputs: string[];
  examples: BridgeExamplePreview[];
  artifactGroups: BridgeArtifactGroup[];
  findings: {
    total: number;
    clean: boolean;
    families: string[];
  };
  tokenRoleNote: string;
};

export type DesignToolBridgeModel = {
  system: {
    title: string;
    release: string;
    badges: string[];
    metrics: BridgeMetric[];
    summary: string;
  };
  sources: BridgeSourceCard[];
  componentList: BridgeComponentListItem[];
  selectedComponent: BridgeComponentDetail;
  verificationReports: BridgeVerificationReport[];
};

const previewTokenPaths = [
  { label: "Surface", path: "color.surface.bg" },
  { label: "Text", path: "color.text.primary" },
  { label: "Border", path: "color.surface.border" },
  { label: "Radius", path: "dimension.radius.md" },
] as const;

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function truncateHash(hash: string): string {
  if (hash.length <= 24) {
    return hash;
  }
  return `${hash.slice(0, 16)}...${hash.slice(-8)}`;
}

function formatStatus(value: string): string {
  return value
    .split(/[-_]/g)
    .filter(Boolean)
    .map((segment) => segment.slice(0, 1).toUpperCase() + segment.slice(1))
    .join(" ");
}

function diagnosticsForSource(sourceId: string): DiagnosticsProjection | null {
  return catalogBridgeSource.diagnosticsBySourceId[sourceId as keyof typeof catalogBridgeSource.diagnosticsBySourceId] ?? null;
}

function artifactsForSource(sourceId: string): ArtifactReference[] {
  return catalogBridgeSource.systemCatalog.catalogSystem.artifactReferences.filter(
    (artifact) => artifact.sourceId === sourceId,
  );
}

function tokenContextById(contextId: string): TokenContext | undefined {
  return catalogBridgeSource.tokenContexts.find((context) => context.context === contextId);
}

function tokenValueForPath(contextId: string, path: string): { value: string; swatch?: string } {
  const context = tokenContextById(contextId);
  const token = context?.tokens.find((candidate) => candidate.path === path);
  if (!token) {
    return { value: "Unavailable" };
  }
  if (token.type === "color" && typeof token.value === "object" && "hex" in token.value) {
    return {
      value: token.value.hex,
      swatch: token.value.hex,
    };
  }
  if (token.type === "dimension" && typeof token.value === "object" && "value" in token.value) {
    return {
      value: `${token.value.value}${token.value.unit}`,
    };
  }
  return {
    value: JSON.stringify(token.value),
  };
}

function artifactGroupsForComponent(component: CatalogComponent): BridgeArtifactGroup[] {
  const grouped = new Map<string, BridgeArtifactGroup>();

  for (const artifact of component.artifactReferences) {
    const group =
      grouped.get(artifact.backendId) ??
      {
        backendId: artifact.backendId,
        artifacts: [],
      };
    group.artifacts.push({
      kind: artifact.kind,
      file: artifact.file,
      size: formatBytes(artifact.size),
      apiVersion: artifact.apiVersion,
    });
    grouped.set(artifact.backendId, group);
  }

  return [...grouped.values()];
}

function summarizeFamilies(total: number, families: Array<{ familyLabel: string; count: number }>): string[] {
  if (total === 0 || families.length === 0) {
    return ["No findings"];
  }
  return families.map((family) => `${family.familyLabel} (${family.count})`);
}

function componentDetail(component: CatalogComponent): BridgeComponentDetail {
  return {
    id: component.id,
    title: component.title,
    status: formatStatus(component.status),
    description: component.description,
    compatibilityLabel: component.compatibility.contractComponent,
    accessibilityNotes: component.accessibility.notes,
    parts: component.parts.map((part) => `${part.name}: ${part.description}`),
    slots: component.slots.map((slot) => `${slot.name}: ${slot.description}`),
    inputs: component.inputs.map((input) => {
      const details = input.kind === "enum" ? `${input.label} (${input.default})` : input.label;
      return `${details} - ${input.description}`;
    }),
    examples: component.examples.map((example) => ({
      label: example.label,
      context: example.context,
      inputs: Object.entries(example.inputs).map(([key, value]) => `${key}: ${String(value)}`),
      contentLabel: example.content.label,
      tokenPreview: previewTokenPaths.map((preview) => {
        const tokenValue = tokenValueForPath(example.context, preview.path);
        return {
          label: preview.label,
          value: tokenValue.value,
          swatch: tokenValue.swatch,
        };
      }),
    })),
    artifactGroups: artifactGroupsForComponent(component),
    findings: {
      total: component.verificationSummary.total,
      clean: component.verificationSummary.clean,
      families: summarizeFamilies(component.verificationSummary.total, component.verificationSummary.families),
    },
    tokenRoleNote:
      component.tokenRoleBindings.length > 0
        ? `${component.tokenRoleBindings.length} semantic token-role bindings`
        : "Token-role bindings are intentionally still empty in alpha; the bridge does not infer them from web-only style hooks.",
  };
}

function sourceCards(): BridgeSourceCard[] {
  return catalogBridgeSource.systemCatalog.catalogSystem.paintSources.map((source) => {
    const diagnostics = diagnosticsForSource(source.id);
    const artifacts = artifactsForSource(source.id);
    return {
      id: source.id,
      label: source.id.toUpperCase(),
      manifest: source.manifest,
      diagnostics: source.diagnostics,
      spec: source.spec,
      toolVersion: `${source.tool.name} ${source.tool.version}`,
      pack: `${source.packIdentity.packId} ${source.packIdentity.packVersion}`,
      packHash: truncateHash(source.packIdentity.contentHash),
      artifactCount: artifacts.length,
      findingCount: diagnostics?.summary.total ?? 0,
      clean: diagnostics?.summary.clean ?? true,
    };
  });
}

function verificationReports(): BridgeVerificationReport[] {
  return catalogBridgeSource.systemCatalog.catalogSystem.verificationSummary.reports.map((report) => {
    const diagnostics = diagnosticsForSource(report.sourceId);
    return {
      sourceId: report.sourceId,
      reportFile: report.file,
      backendIds: report.backendIds,
      findingCount: diagnostics?.summary.total ?? report.total,
      clean: diagnostics?.summary.clean ?? report.clean,
      families: summarizeFamilies(diagnostics?.summary.total ?? report.total, diagnostics?.summary.families ?? []),
      sourceReportFile: diagnostics?.sourceReport.file ?? "validation.json",
    };
  });
}

export function buildDesignToolBridgeModel(selectedComponentId?: string): DesignToolBridgeModel {
  const componentCards = catalogBridgeSource.systemCatalog.catalogComponents.map((component) => ({
    id: component.id,
    title: component.title,
    status: formatStatus(component.status),
    description: component.description,
    exampleCount: component.examples.length,
    inputCount: component.inputs.length,
    findingCount: component.verificationSummary.total,
    clean: component.verificationSummary.clean,
  }));

  const selectedComponent =
    catalogBridgeSource.systemCatalog.catalogComponents.find(
      (component) => component.id === selectedComponentId,
    ) ?? catalogBridgeSource.systemCatalog.catalogComponents[0];

  return {
    system: {
      title: catalogBridgeSource.systemCatalog.catalogSystem.title,
      release: catalogBridgeSource.systemCatalog.catalogSystem.release,
      badges: [
        "Read-only bridge",
        catalogBridgeSource.systemCatalog.catalogSystem.catalogVersion,
        catalogBridgeSource.tokenApiVersion,
      ],
      metrics: [
        {
          label: "Components",
          value: String(catalogBridgeSource.systemCatalog.catalogComponents.length),
        },
        {
          label: "Artifacts",
          value: String(catalogBridgeSource.systemCatalog.catalogSystem.artifactReferences.length),
        },
        {
          label: "Reports",
          value: String(catalogBridgeSource.systemCatalog.catalogSystem.verificationSummary.reports.length),
        },
      ],
      summary:
        "This surface behaves like a design-tool catalog browser: it reads the neutral catalog IR, verification projections, and generated token package output, but it does not become an authoring source.",
    },
    sources: sourceCards(),
    componentList: componentCards,
    selectedComponent: componentDetail(selectedComponent),
    verificationReports: verificationReports(),
  };
}
