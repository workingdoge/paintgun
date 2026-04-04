import { expect, test } from "bun:test";
import { buildDesignToolBridgeModel } from "../src/model/bridge.ts";

test("design-tool bridge model stays catalog-first and surfaces token previews", () => {
  const model = buildDesignToolBridgeModel();

  expect(model.system.title).toContain("Paint Web Runtime Prototype");
  expect(model.sources.length).toBeGreaterThan(0);
  expect(model.verificationReports.length).toBeGreaterThan(0);
  expect(model.selectedComponent.id).toBe("button");
  expect(model.selectedComponent.findings.clean).toBe(true);
  expect(model.selectedComponent.examples.length).toBeGreaterThan(0);
  expect(model.selectedComponent.examples[0]?.tokenPreview.length).toBeGreaterThan(0);
  expect(model.selectedComponent.tokenRoleNote).toContain("alpha");
  expect(model.sources[0]?.manifest).toContain("ctc.manifest.json");
});
