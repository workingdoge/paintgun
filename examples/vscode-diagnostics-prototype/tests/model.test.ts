import { expect, test } from "bun:test";

import diagnostics from "../fixtures/read-only-demo/dist/diagnostics.pack.json";
import { buildDiagnosticsDocumentModel } from "../src/model";

test("builds a read-only diagnostics document model from the generated projection", () => {
  const model = buildDiagnosticsDocumentModel(
    "fixtures/read-only-demo/dist/diagnostics.pack.json",
    diagnostics,
  );

  expect(model.description).toContain("pack");
  expect(model.findings).toHaveLength(1);
  expect(model.findings[0]?.label).toBe("Missing definition");
  expect(model.findings[0]?.summary).toContain("no explicit winning value");
  expect(model.findings[0]?.nextAction).toContain("Author an explicit value");
});
