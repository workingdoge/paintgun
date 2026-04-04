import { expect, test } from "bun:test";

import { getCatalogComponentById, systemCatalog } from "../src/generated/system-catalog.ts";

test("catalog IR stays design-tool-neutral and keeps system-scoped provenance", () => {
  expect(systemCatalog.catalogSystem.catalogVersion).toBe("paint.catalog.ir.alpha1");
  expect(systemCatalog.catalogSystem.paintSources.length).toBeGreaterThan(0);
  expect(systemCatalog.catalogSystem.verificationSummary.scope).toBe("system");

  const component = getCatalogComponentById("button");
  expect(component.title).toBe("Paint Button");
  expect(component.artifactScope).toBe("system-wide");
  expect(component.tokenRoleBindings).toEqual([]);
  expect(component.verificationSummary.scope).toBe("system-wide");
  expect(component).not.toHaveProperty("tagName");
  expect(component).not.toHaveProperty("styleHooks");
});
