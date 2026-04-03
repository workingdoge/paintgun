import {
  type WebComponent,
} from "../generated/system-web.ts";
import { stylesheetArtifacts, type StoryArgs } from "../model/design-system.ts";

function normalizeArtifactBaseHref(artifactBaseHref: string): string {
  if (!artifactBaseHref) {
    return "";
  }
  return artifactBaseHref.endsWith("/") ? artifactBaseHref : `${artifactBaseHref}/`;
}

export function resolveArtifactHref(file: string, artifactBaseHref = ""): string {
  return `${normalizeArtifactBaseHref(artifactBaseHref)}${file}`;
}

export function stylesheetHrefs(component: WebComponent, artifactBaseHref = ""): string[] {
  return stylesheetArtifacts(component).map((artifact) =>
    resolveArtifactHref(artifact.file, artifactBaseHref),
  );
}

export function applyArgsToElement(
  element: HTMLElement,
  component: WebComponent,
  args: StoryArgs,
) {
  for (const input of component.inputs) {
    const value = args[input.name];
    if (input.kind === "boolean") {
      if (value) {
        element.setAttribute(input.attribute, "");
      } else {
        element.removeAttribute(input.attribute);
      }
      continue;
    }

    const nextValue = typeof value === "string" ? value : String(input.default);
    if (nextValue === String(input.default)) {
      element.removeAttribute(input.attribute);
    } else {
      element.setAttribute(input.attribute, nextValue);
    }
  }

  const label = args.label;
  element.textContent = typeof label === "string" ? label : defaultExample(component).label;
  return element;
}
