import { describe, expect, test } from "bun:test";
import {
  artifactViewModels,
  getPrototypeComponent,
} from "../src/model/design-system.ts";
import { buildComponentShowcaseModel } from "../src/model/showcase.ts";

describe("design-system view model", () => {
  test("builds a reusable showcase model above the shared web runtime IR", () => {
    const showcase = buildComponentShowcaseModel("paint-button");

    expect(showcase.systemTitle).toBe("Paint Web Runtime Prototype");
    expect(showcase.examples.map((example) => example.label)).toEqual([
      "Ship changes",
      "Promote release",
      "Defer publish",
    ]);
    expect(showcase.tokenPreview.entries).toEqual([
      expect.objectContaining({
        token: "color.surface.bg",
        type: "color",
        value: "#f5f6f8",
        detail: "oklch",
      }),
      expect.objectContaining({
        token: "color.text.primary",
        type: "color",
        value: "#1a1a1a",
        detail: "oklch",
      }),
      expect.objectContaining({
        token: "dimension.radius.md",
        type: "dimension",
        value: "8px",
        detail: null,
      }),
    ]);
  });

  test("captures required and optional artifact bindings with display metadata", () => {
    const component = getPrototypeComponent("paint-button");
    const artifacts = artifactViewModels(component);

    expect(artifacts.map((artifact) => artifact.requirement)).toEqual([
      "required",
      "required",
      "optional",
      "optional",
    ]);
    expect(artifacts[0]).toEqual(
      expect.objectContaining({
        kindLabel: "Token Stylesheet",
        backendId: "web-css-vars",
      }),
    );
    expect(artifacts[1]).toEqual(
      expect.objectContaining({
        detail: "paintgun-web-tokens-ts/v1",
        backendId: "web-tokens-ts",
      }),
    );
  });
});
