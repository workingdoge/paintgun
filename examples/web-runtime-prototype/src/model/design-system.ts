import { valuesByContext } from "../../generated/paint/web/tokens.ts";
import {
  getWebComponentByTagName,
  type WebArtifact,
  type WebComponent,
  type WebExample,
  webRuntime,
} from "../generated/system-web.ts";

export type StoryArgs = Record<string, string | boolean>;

type TokenContext = keyof typeof valuesByContext;
type TokenRecord = (typeof valuesByContext)[TokenContext];
type TokenValue = TokenRecord[keyof TokenRecord];

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

export type ExampleInputViewModel = {
  label: string;
  value: string;
};

export type ExampleViewModel = {
  args: StoryArgs;
  context: string;
  id: string;
  inputs: ExampleInputViewModel[];
  label: string;
  slotLabel: string;
};

export type TokenPreviewEntry = {
  detail: string | null;
  token: string;
  type: string;
  value: string;
};

export type ComponentShowcaseModel = {
  artifacts: ArtifactViewModel[];
  component: WebComponent;
  examples: ExampleViewModel[];
  lede: string;
  summary: string;
  systemTitle: string;
  tokenPreview: {
    context: string;
    entries: TokenPreviewEntry[];
  };
};

function defaultExample(component: WebComponent): WebExample {
  const example = component.examples[0];
  if (!example) {
    throw new Error(`component ${component.id} is missing example metadata`);
  }
  return example;
}

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

function formatTokenValue(token: TokenValue): Omit<TokenPreviewEntry, "token"> {
  if (token.type === "color" && token.value && typeof token.value === "object") {
    const detail =
      "colorSpace" in token.value && typeof token.value.colorSpace === "string"
        ? token.value.colorSpace
        : null;
    const value =
      "hex" in token.value && typeof token.value.hex === "string"
        ? token.value.hex
        : JSON.stringify(token.value);
    return {
      detail,
      type: token.type,
      value,
    };
  }

  if (
    (token.type === "dimension" || token.type === "duration") &&
    token.value &&
    typeof token.value === "object" &&
    "value" in token.value &&
    typeof token.value.value === "string"
  ) {
    const unit =
      "unit" in token.value && typeof token.value.unit === "string" ? token.value.unit : "";
    return {
      detail: null,
      type: token.type,
      value: `${token.value.value}${unit}`,
    };
  }

  return {
    detail: null,
    type: token.type,
    value: JSON.stringify(token.value),
  };
}

function inputSummary(component: WebComponent, args: StoryArgs): ExampleInputViewModel[] {
  return component.inputs.map((input) => {
    const currentValue = args[input.name];
    const value =
      input.kind === "boolean"
        ? currentValue
          ? "On"
          : "Off"
        : typeof currentValue === "string"
          ? currentValue
          : String(input.default);
    return {
      label: input.label,
      value,
    };
  });
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

export function exampleViewModels(component: WebComponent): ExampleViewModel[] {
  return component.examples.map((example) => ({
    args: { ...example.args },
    context: example.context,
    id: example.id,
    inputs: inputSummary(component, example.args),
    label: example.label,
    slotLabel: typeof example.args.label === "string" ? example.args.label : example.label,
  }));
}

export function tokenPreviewEntries(context: string, tokenNames: string[]): TokenPreviewEntry[] {
  const contextTokens = valuesByContext[context as keyof typeof valuesByContext];
  if (!contextTokens) {
    throw new Error(`unknown token preview context: ${context}`);
  }

  return tokenNames.map((tokenName) => {
    const token = contextTokens[tokenName as keyof typeof contextTokens];
    if (!token) {
      throw new Error(`missing token preview value for ${tokenName}`);
    }
    const preview = formatTokenValue(token);
    return {
      ...preview,
      token: tokenName,
    };
  });
}

export function buildComponentShowcaseModel(tagName = "paint-button"): ComponentShowcaseModel {
  const component = getPrototypeComponent(tagName);
  const primaryExample = defaultExample(component);
  const tokenNames = ["color.surface.bg", "color.text.primary", "dimension.radius.md"];

  return {
    artifacts: artifactViewModels(component),
    component,
    examples: exampleViewModels(component),
    lede:
      "This host reads a shared design-system view model derived from the web runtime IR. The custom element, Storybook stories, and this page stay consumers of the same generated truth.",
    summary: `${component.title} exposes ${component.inputs.length} runtime inputs, ${component.events.length} custom event, and ${component.examples.length} authored example variants over Paint-generated artifacts.`,
    systemTitle: webRuntime.webSystem.title,
    tokenPreview: {
      context: primaryExample.context,
      entries: tokenPreviewEntries(primaryExample.context, tokenNames),
    },
  };
}
