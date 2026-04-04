import {
  buildComponentShowcaseModel,
} from "../model/showcase.ts";
import {
  exampleArgs,
  previewTokenArtifact,
} from "../model/runtime.ts";
import { storyArgTypes } from "../model/storybook.ts";
import {
  applyArgsToElement,
  stylesheetHrefs,
} from "../runtime/web-runtime.ts";
import { registerPaintPrototype } from "../register.ts";

registerPaintPrototype();

const showcase = buildComponentShowcaseModel("paint-button");
const component = showcase.component;
const defaultArgs = exampleArgs(component, "default");
const accentArgs = exampleArgs(component, "accent");
const outlineArgs = exampleArgs(component, "outline");

export function renderPaintButton(args: Record<string, string | boolean>) {
  const element = document.createElement(component.tagName);
  return applyArgsToElement(element, component, args);
}

const meta = {
  title: "Components/Paint Button",
  tags: ["autodocs"],
  parameters: {
    layout: "centered",
    docs: {
      description: {
        component: component.description,
      },
    },
    paintRuntime: {
      componentId: component.id,
      requiredStylesheets: stylesheetHrefs(component),
      previewTokenArtifact: previewTokenArtifact(component),
      previewTokens: showcase.tokenPreview.entries,
    },
  },
  args: defaultArgs,
  argTypes: {
    ...storyArgTypes(component),
    label: {
      control: "text",
      description: "Fallback slot content used in the example story.",
      table: {
        category: "example",
      },
    },
  },
};

export default meta;

export const Default = {
  args: defaultArgs,
  render: renderPaintButton,
};

export const Accent = {
  args: accentArgs,
  render: renderPaintButton,
};

export const Outline = {
  args: outlineArgs,
  render: renderPaintButton,
};
