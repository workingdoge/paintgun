import type { WebArtifact, WebComponent } from "./runtime.ts";

export type ArtifactRequirement = "required" | "optional";

export type ArtifactViewModel = {
  artifactId: string;
  backendId: string;
  detail: string | null;
  file: string;
  kind: string;
  kindLabel: string;
  requirement: ArtifactRequirement;
  sizeLabel: string;
};

function humanizeIdentifier(value: string): string {
  const spaced = value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[-_]/g, " ")
    .trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function formatArtifactSize(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  return `${(size / 1024).toFixed(1)} KB`;
}

export function artifactViewModels(component: WebComponent): ArtifactViewModel[] {
  return [
    ...component.artifacts.required.map((artifact) => ({
      ...artifact,
      requirement: "required" as const,
    })),
    ...component.artifacts.optional.map((artifact) => ({
      ...artifact,
      requirement: "optional" as const,
    })),
  ].map((artifact) => ({
    artifactId: artifact.artifactId,
    backendId: artifact.backendId,
    detail: artifact.apiVersion ?? null,
    file: artifact.file,
    kind: artifact.kind,
    kindLabel: humanizeIdentifier(artifact.kind),
    requirement: artifact.requirement,
    sizeLabel: formatArtifactSize(artifact.size),
  }));
}

export function allArtifacts(component: WebComponent): WebArtifact[] {
  return [...component.artifacts.required, ...component.artifacts.optional];
}
