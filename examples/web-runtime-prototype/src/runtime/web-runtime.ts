import {
  getArtifactUrl,
  type WebArtifact,
  type WebComponent,
  type WebExample,
} from "../generated/system-web.ts";

type StoryArgs = Record<string, string | boolean>;

function defaultExample(component: WebComponent): WebExample {
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

export function stylesheetArtifacts(component: WebComponent): WebArtifact[] {
  return [...component.artifacts.required, ...component.artifacts.optional].filter(
    (artifact) =>
      artifact.kind === "tokenStylesheet" || artifact.kind === "systemStylesheet",
  );
}

export function stylesheetHrefs(component: WebComponent): string[] {
  return stylesheetArtifacts(component).map((artifact) => getArtifactUrl(artifact.file).pathname);
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

export function storyArgTypes(component: WebComponent) {
  return Object.fromEntries(
    component.inputs.map((input) => {
      const control =
        input.kind === "boolean"
          ? "boolean"
          : {
              type: "inline-radio",
            };

      return [
        input.name,
        {
          control,
          ...(input.options ? { options: [...input.options] } : {}),
          description: input.description,
          table: {
            category: "web runtime input",
            defaultValue: {
              summary: String(input.default),
            },
          },
        },
      ];
    }),
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
