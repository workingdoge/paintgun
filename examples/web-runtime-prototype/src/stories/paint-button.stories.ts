import { valuesByContext } from "../../generated/paint/web/tokens.ts";
import { getWebComponentByTagName } from "../generated/system-web.ts";
import {
  applyArgsToElement,
  exampleArgs,
  previewTokenArtifact,
  storyArgTypes,
  stylesheetHrefs,
} from "../runtime/web-runtime.ts";
import { registerPaintPrototype } from "../register.ts";

registerPaintPrototype();

const component = getWebComponentByTagName("paint-button");
const defaultArgs = exampleArgs(component, "default");
const accentArgs = exampleArgs(component, "accent");
const outlineArgs = exampleArgs(component, "outline");
const previewTokens = valuesByContext["mode:docs,theme:light"];

export function renderPaintButton(args: Record<string, string | boolean>) {
  const element = document.createElement(component.tagName);
  return applyArgsToElement(element, component, args);
}

const meta = {
  title: "Prototype/Paint Button",
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
      previewTokens: {
        "color.surface.bg": previewTokens["color.surface.bg"],
        "color.text.primary": previewTokens["color.text.primary"],
      },
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
