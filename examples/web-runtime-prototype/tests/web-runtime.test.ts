import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import {
  getWebComponentByTagName,
  webRuntime,
} from "../src/generated/system-web.ts";
import { resolveArtifactHref } from "../src/runtime/web-runtime.ts";

const exampleRoot = resolve(import.meta.dir, "..");

describe("shared web runtime adapter", () => {
  test("pins the prototype to real Paint backend artifacts", () => {
    const component = getWebComponentByTagName("paint-button");

    expect(component.artifacts.required.map((artifact) => artifact.kind)).toEqual([
      "tokenStylesheet",
      "primaryTokenOutput",
    ]);

    expect(component.artifacts.optional.map((artifact) => artifact.kind)).toEqual([
      "systemStylesheet",
      "typeDeclarations",
    ]);

    for (const artifact of [
      ...component.artifacts.required,
      ...component.artifacts.optional,
    ]) {
      const artifactPath = join(exampleRoot, artifact.file);
      expect(existsSync(artifactPath)).toBe(true);
      expect(resolveArtifactHref(artifact.file, "../")).toBe(`../${artifact.file}`);
    }
  });

  test("records both Paint sources in the web system metadata", () => {
    expect(webRuntime.webSystem.paintSources.map((source) => source.id)).toEqual([
      "paintCss",
      "paintWeb",
    ]);
  });
});
