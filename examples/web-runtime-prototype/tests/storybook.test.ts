import { beforeEach, describe, expect, test } from "bun:test";
import meta, {
  Accent,
  Default,
  Outline,
  renderPaintButton,
} from "../src/stories/paint-button.stories.ts";

beforeEach(() => {
  document.body.innerHTML = "";
});

describe("storybook consumer", () => {
  test("derives its controls and supporting assets from the shared web runtime", () => {
    expect(meta.title).toBe("Prototype/Paint Button");
    expect(meta.argTypes.tone.options).toEqual(["neutral", "accent"]);
    expect(meta.argTypes.emphasis.options).toEqual(["solid", "outline"]);
    expect(meta.parameters.paintRuntime.requiredStylesheets).toEqual([
      expect.stringContaining("generated/paint/css/tokens.vars.css"),
      expect.stringContaining("generated/paint/css/components.css"),
    ]);
    expect(meta.parameters.paintRuntime.previewTokenArtifact.backendId).toBe("web-tokens-ts");
    expect(meta.parameters.paintRuntime.previewTokens).toEqual([
      expect.objectContaining({
        token: "color.surface.bg",
        value: "#f5f6f8",
      }),
      expect.objectContaining({
        token: "color.text.primary",
        value: "#1a1a1a",
      }),
      expect.objectContaining({
        token: "dimension.radius.md",
        value: "8px",
      }),
    ]);
  });

  test("renders stories as real custom elements instead of story-owned truth", () => {
    const defaultElement = Default.render(Default.args);
    const accentElement = Accent.render(Accent.args);
    const outlineElement = Outline.render(Outline.args);

    expect(defaultElement.tagName.toLowerCase()).toBe("paint-button");
    expect(accentElement.getAttribute("tone")).toBe("accent");
    expect(outlineElement.getAttribute("emphasis")).toBe("outline");

    const explicit = renderPaintButton({
      ...Default.args,
      label: "Review architecture",
    });
    expect(explicit.textContent).toBe("Review architecture");
  });
});
