import {
  getWebComponentByTagName,
  type WebArtifact,
  type WebComponent,
  type WebExample,
  webRuntime,
} from "../generated/system-web.ts";

export type StoryArgs = Record<string, string | boolean>;

export function defaultExample(component: WebComponent): WebExample {
  const example = component.examples[0];
  if (!example) {
    throw new Error(`component ${component.id} is missing example metadata`);
  }
  return example;
}

export function exampleArgs(component: WebComponent, exampleId?: string): StoryArgs {
  const example =
    component.examples.find((candidate) => candidate.id === exampleId) ?? defaultExample(component);
  return { ...example.args };
}

export function getPrototypeComponent(tagName = "paint-button"): WebComponent {
  return getWebComponentByTagName(tagName);
}

export function stylesheetArtifacts(component: WebComponent): WebArtifact[] {
  return [...component.artifacts.required, ...component.artifacts.optional].filter(
    (artifact) =>
      artifact.kind === "tokenStylesheet" || artifact.kind === "systemStylesheet",
  );
}

export function previewTokenArtifact(component: WebComponent): WebArtifact {
  const artifact = [...component.artifacts.required, ...component.artifacts.optional].find(
    (candidate) => candidate.kind === "primaryTokenOutput",
  );
  if (!artifact) {
    throw new Error(`component ${component.id} is missing a primary token output artifact`);
  }
  return artifact;
}

export { webRuntime };
export type { WebArtifact, WebComponent, WebExample };
