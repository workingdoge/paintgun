import { afterEach, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { mountDesignToolBridge } from "../src/main.ts";

let activeWindow: Window | null = null;

afterEach(() => {
  activeWindow?.close();
  activeWindow = null;
});

test("bridge UI renders read-only catalog and verification sections", () => {
  activeWindow = new Window();
  const document = activeWindow.document;
  const root = document.createElement("div");
  document.body.append(root);

  mountDesignToolBridge(root);

  expect(root.textContent).toContain("Paint Design-Tool Bridge");
  expect(root.textContent).toContain("Read-only bridge");
  expect(root.textContent).toContain("Selected component");
  expect(root.textContent).toContain("Verification and provenance");
  expect([...root.getElementsByTagName("button")].filter((button) => button.dataset.componentId).length).toBeGreaterThan(0);
});
