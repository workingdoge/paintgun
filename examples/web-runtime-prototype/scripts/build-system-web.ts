import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, normalize, resolve } from "node:path";

type ArtifactDescriptor = {
  backendId: string;
  kind: string;
  file: string;
  sha256: string;
  size: number;
  apiVersion?: string;
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
  };
  backendArtifacts: ArtifactDescriptor[];
};

type ArtifactBinding = {
  id: string;
  source: string;
  kind: string;
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
  content?: {
    label?: string;
  };
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
    compatibility: {
      contractComponent: string;
    };
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

type WebProjection = {
  projectionVersion: string;
  artifactSources: Record<string, { manifest: string }>;
  components: Array<{
    componentId: string;
    tagName: string;
    inputBindings: Array<{
      input: string;
      attribute: string;
      property: string;
    }>;
    events: Array<{
      name: string;
      detail: Record<string, string>;
      bubbles: boolean;
      composed: boolean;
    }>;
    styleHooks: Array<{ name: string; source: string; token: string }>;
    artifactBindings: {
      required: ArtifactBinding[];
      optional: ArtifactBinding[];
    };
  }>;
};

const exampleRoot = resolve(import.meta.dir, "..");
const schemaPath = join(exampleRoot, "system.schema.json");
const projectionPath = join(exampleRoot, "system.web.config.json");
const outputPath = join(exampleRoot, "generated", "system.web.json");

function fromExampleRoot(path: string) {
  return normalize(path).replace(/\\/g, "/");
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

function indexById<T extends { id: string }>(records: T[]): Record<string, T> {
  return Object.fromEntries(records.map((record) => [record.id, record]));
}

function indexByName<T extends { name: string }>(records: T[]): Record<string, T> {
  return Object.fromEntries(records.map((record) => [record.name, record]));
}

function propertyTypeForInput(input: SystemInput): string {
  if (input.kind === "boolean") {
    return "boolean";
  }
  if (input.kind === "enum" && input.options && input.options.length > 0) {
    return input.options.map((option) => JSON.stringify(option)).join(" | ");
  }
  return typeof input.default === "string" ? "string" : "unknown";
}

function resolveArtifactBinding(
  binding: ArtifactBinding,
  sourcePath: string,
  manifest: Manifest,
) {
  const descriptor = manifest.backendArtifacts.find((artifact) => artifact.kind === binding.kind);
  if (!descriptor) {
    throw new Error(`missing artifact kind ${binding.kind} in ${sourcePath}`);
  }

  const manifestDir = dirname(sourcePath);
  const absoluteFile = resolve(manifestDir, descriptor.file);
  const relativeFile = fromExampleRoot(absoluteFile.slice(exampleRoot.length + 1));

  return {
    artifactId: binding.id,
    source: binding.source,
    backendId: descriptor.backendId,
    kind: descriptor.kind,
    file: relativeFile,
    sha256: descriptor.sha256,
    size: descriptor.size,
    ...(descriptor.apiVersion ? { apiVersion: descriptor.apiVersion } : {}),
  };
}

function buildWebExamples(examples: SystemExample[]) {
  return examples.map((example) => ({
    id: example.id,
    label: example.label,
    context: example.context,
    args: {
      ...example.inputs,
      ...(example.content?.label ? { label: example.content.label } : {}),
    },
  }));
}

const schema = await readJson<SystemSchema>(schemaPath);
const projection = await readJson<WebProjection>(projectionPath);

const manifests = await Promise.all(
  Object.entries(projection.artifactSources).map(async ([sourceId, source]) => {
    const manifestPath = join(exampleRoot, source.manifest);
    const manifest = await readJson<Manifest>(manifestPath);
    return [sourceId, { manifestPath, manifest }] as const;
  }),
);

const manifestsBySource = Object.fromEntries(manifests);
const componentsById = indexById(schema.components);

const webRuntime = {
  webSystem: {
    id: schema.system.id,
    title: schema.system.title,
    release: schema.system.release,
    schemaVersion: schema.schemaVersion,
    projectionVersion: projection.projectionVersion,
    paintSources: Object.entries(manifestsBySource).map(([sourceId, value]) => ({
      id: sourceId,
      manifest: fromExampleRoot(value.manifestPath.slice(exampleRoot.length + 1)),
      tool: value.manifest.tool,
      spec: value.manifest.spec,
      packIdentity: value.manifest.packIdentity,
    })),
  },
  webComponents: projection.components.map((projectionComponent) => {
    const component = componentsById[projectionComponent.componentId];
    if (!component) {
      throw new Error(`unknown projection component id: ${projectionComponent.componentId}`);
    }

    const inputsByName = indexByName(component.inputs);
    const inputBindingsByName = Object.fromEntries(
      projectionComponent.inputBindings.map((binding) => [binding.input, binding]),
    );

    for (const input of component.inputs) {
      if (!inputBindingsByName[input.name]) {
        throw new Error(
          `missing web input binding for ${component.id}.${input.name}`,
        );
      }
    }

    for (const binding of projectionComponent.inputBindings) {
      if (!inputsByName[binding.input]) {
        throw new Error(`unknown web input binding for ${component.id}.${binding.input}`);
      }
    }

    return {
      id: component.id,
      tagName: projectionComponent.tagName,
      title: component.title,
      description: component.description,
      status: component.status,
      compatibility: component.compatibility,
      accessibility: component.accessibility,
      parts: component.surfaces.parts,
      slots: component.surfaces.slots,
      inputs: component.inputs.map((input) => {
        const binding = inputBindingsByName[input.name];
        return {
          ...input,
          attribute: binding.attribute,
          property: binding.property,
        };
      }),
      properties: component.inputs.map((input) => {
        const binding = inputBindingsByName[input.name];
        return {
          name: binding.property,
          type: propertyTypeForInput(input),
        };
      }),
      events: projectionComponent.events,
      styleHooks: projectionComponent.styleHooks,
      artifacts: {
        required: projectionComponent.artifactBindings.required.map((binding) =>
          resolveArtifactBinding(
            binding,
            manifestsBySource[binding.source].manifestPath,
            manifestsBySource[binding.source].manifest,
          ),
        ),
        optional: projectionComponent.artifactBindings.optional.map((binding) =>
          resolveArtifactBinding(
            binding,
            manifestsBySource[binding.source].manifestPath,
            manifestsBySource[binding.source].manifest,
          ),
        ),
      },
      examples: buildWebExamples(component.examples),
    };
  }),
};

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(webRuntime, null, 2)}\n`, "utf8");
console.log(`wrote ${outputPath}`);
