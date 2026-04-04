import assert from "node:assert/strict";

import {
  availableInputs,
  buildSurfacePreview,
  resolveContext,
  tokenValue,
} from "../src/index";

const input = { mode: "docs", theme: "light" } as const;

assert.equal(availableInputs().length, 4, "expected all generated context inputs");
assert.equal(
  resolveContext(input),
  "mode:docs,theme:light",
  "expected stable context resolution",
);

const surface = tokenValue(input, "color.surface.bg");
assert.equal(surface.hex, "#f5f6f8", "expected light surface background token");

const radius = tokenValue(input, "dimension.radius.md");
assert.equal(`${radius.value}${radius.unit}`, "8px", "expected medium radius token");

const preview = buildSurfacePreview(input);
assert.equal(preview.duration, "200ms", "expected transition duration preview");
assert.equal(preview.background, "#f5f6f8", "expected background preview");

console.log("verified web-tokens-ts consumer example");
