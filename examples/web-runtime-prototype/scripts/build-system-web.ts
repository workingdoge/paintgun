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

type Schema = {
  schemaVersion: string;
  system: {
    id: string;
    title: string;
    release: string;
  };
  artifactSources: Record<string, { manifest: string }>;
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
    web: {
      tagName: string;
      parts: Array<{ name: string; description: string }>;
      slots: Array<{ name: string; description: string }>;
      inputs: Array<{
        name: string;
        label: string;
        description: string;
        kind: string;
        attribute: string;
        property: string;
        default: string | boolean;
        options?: string[];
      }>;
      properties: Array<{ name: string; type: string }>;
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
      examples: Array<{
        id: string;
        label: string;
        context: string;
        args: Record<string, string | boolean>;
      }>;
    };
  }>;
};

const exampleRoot = resolve(import.meta.dir, "..");
const schemaPath = join(exampleRoot, "system.schema.json");
const outputPath = join(exampleRoot, "generated", "system.web.json");

function fromExampleRoot(path: string) {
  return normalize(path).replace(/\\/g, "/");
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
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

const schema = await readJson<Schema>(schemaPath);

const manifests = await Promise.all(
  Object.entries(schema.artifactSources).map(async ([sourceId, source]) => {
    const manifestPath = join(exampleRoot, source.manifest);
    const manifest = await readJson<Manifest>(manifestPath);
    return [sourceId, { manifestPath, manifest }] as const;
  }),
);

const manifestsBySource = Object.fromEntries(manifests);

const webRuntime = {
  webSystem: {
    id: schema.system.id,
    title: schema.system.title,
    release: schema.system.release,
    schemaVersion: schema.schemaVersion,
    paintSources: Object.entries(manifestsBySource).map(([sourceId, value]) => ({
      id: sourceId,
      manifest: fromExampleRoot(value.manifestPath.slice(exampleRoot.length + 1)),
      tool: value.manifest.tool,
      spec: value.manifest.spec,
      packIdentity: value.manifest.packIdentity,
    })),
  },
  webComponents: schema.components.map((component) => ({
    id: component.id,
    tagName: component.web.tagName,
    title: component.title,
    description: component.description,
    status: component.status,
    compatibility: component.compatibility,
    accessibility: component.accessibility,
    parts: component.web.parts,
    slots: component.web.slots,
    inputs: component.web.inputs,
    properties: component.web.properties,
    events: component.web.events,
    styleHooks: component.web.styleHooks,
    artifacts: {
      required: component.web.artifactBindings.required.map((binding) =>
        resolveArtifactBinding(
          binding,
          manifestsBySource[binding.source].manifestPath,
          manifestsBySource[binding.source].manifest,
        ),
      ),
      optional: component.web.artifactBindings.optional.map((binding) =>
        resolveArtifactBinding(
          binding,
          manifestsBySource[binding.source].manifestPath,
          manifestsBySource[binding.source].manifest,
        ),
      ),
    },
    examples: component.web.examples,
  })),
};

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(webRuntime, null, 2)}\n`, "utf8");
console.log(`wrote ${outputPath}`);
