import { artifactViewModels, type ArtifactViewModel } from "./artifacts.ts";
import {
  defaultExample,
  getPrototypeComponent,
  type StoryArgs,
  webRuntime,
  type WebComponent,
} from "./runtime.ts";
import { tokenPreviewEntries, type TokenPreviewEntry } from "./tokens.ts";

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
