import { valuesByContext } from "../generated/paint/web/tokens.ts";
import { getWebComponentByTagName, webRuntime } from "../src/generated/system-web.ts";
import { applyArgsToElement, stylesheetArtifacts } from "../src/runtime/web-runtime.ts";
import { registerPaintPrototype } from "../src/register.ts";

registerPaintPrototype();

const component = getWebComponentByTagName("paint-button");
const previewContext = component.examples[0]?.context ?? "mode:docs,theme:light";
const previewTokens = valuesByContext[previewContext as keyof typeof valuesByContext];

const title = document.getElementById("demo-title");
const lede = document.getElementById("demo-lede");
const summary = document.getElementById("demo-summary");
const demoGrid = document.getElementById("demo-grid");
const artifactList = document.getElementById("artifact-list");
const tokenPreview = document.getElementById("token-preview");

if (!title || !lede || !summary || !demoGrid || !artifactList || !tokenPreview) {
  throw new Error("demo host is missing required container nodes");
}

title.textContent = webRuntime.webSystem.title;
lede.textContent =
  "This page is a browser host over the shared web runtime IR. The custom element, Storybook story, and this host all read the same generated adapter instead of inventing their own truth.";
summary.textContent = `${component.title} renders from ${component.examples.length} authored example(s) using Paint-generated CSS and token artifacts.`;

for (const example of component.examples) {
  const row = document.createElement("div");
  row.className = "demo-row";

  const label = document.createElement("strong");
  label.textContent = example.label;
  label.style.inlineSize = "12rem";

  const element = document.createElement(component.tagName);
  applyArgsToElement(element, component, example.args);

  row.append(label, element);
  demoGrid.append(row);
}

for (const artifact of stylesheetArtifacts(component)) {
  const item = document.createElement("li");
  item.innerHTML = `<strong>${artifact.kind}</strong><br /><code>${artifact.file}</code>`;
  artifactList.append(item);
}

tokenPreview.textContent = JSON.stringify(
  {
    context: previewContext,
    sample: {
      "color.surface.bg": previewTokens["color.surface.bg"],
      "color.text.primary": previewTokens["color.text.primary"],
      "dimension.radius.md": previewTokens["dimension.radius.md"],
    },
  },
  null,
  2,
);
