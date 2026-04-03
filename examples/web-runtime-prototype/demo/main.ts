import { buildComponentShowcaseModel } from "../src/model/design-system.ts";
import { applyArgsToElement } from "../src/runtime/web-runtime.ts";
import { registerPaintPrototype } from "../src/register.ts";

function requiredElement(document: Document, id: string): HTMLElement {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`demo host is missing required element #${id}`);
  }
  return node;
}

export function startDemo(document: Document = globalThis.document) {
  registerPaintPrototype();

  const showcase = buildComponentShowcaseModel("paint-button");

  const title = requiredElement(document, "demo-title");
  const lede = requiredElement(document, "demo-lede");
  const summary = requiredElement(document, "demo-summary");
  const demoGrid = requiredElement(document, "demo-grid");
  const artifactList = requiredElement(document, "artifact-list");
  const tokenPreview = requiredElement(document, "token-preview");

  demoGrid.replaceChildren();
  artifactList.replaceChildren();

  title.textContent = showcase.systemTitle;
  lede.textContent = showcase.lede;
  summary.textContent = showcase.summary;

  for (const example of showcase.examples) {
    const card = document.createElement("article");
    card.className = "demo-card";

    const header = document.createElement("div");
    header.className = "demo-card-header";

    const label = document.createElement("h3");
    label.textContent = example.label;

    const context = document.createElement("span");
    context.className = "pill";
    context.textContent = example.context;

    header.append(label, context);

    const preview = document.createElement("div");
    preview.className = "demo-card-preview";

    const element = document.createElement(showcase.component.tagName);
    applyArgsToElement(element, showcase.component, example.args);
    preview.append(element);

    const inputs = document.createElement("ul");
    inputs.className = "chip-list";

    for (const input of example.inputs) {
      const item = document.createElement("li");
      item.className = "chip";
      item.innerHTML = `<span>${input.label}</span><strong>${input.value}</strong>`;
      inputs.append(item);
    }

    card.append(header, preview, inputs);
    demoGrid.append(card);
  }

  for (const artifact of showcase.artifacts) {
    const item = document.createElement("li");
    item.innerHTML = `
      <div class="artifact-head">
        <strong>${artifact.kindLabel}</strong>
        <span class="pill ${artifact.requirement}">${artifact.requirement}</span>
      </div>
      <div class="artifact-meta">
        <span>${artifact.backendId}</span>
        <span>${artifact.sizeLabel}</span>
      </div>
      <code>${artifact.file}</code>
      ${artifact.detail ? `<p class="artifact-detail">${artifact.detail}</p>` : ""}
    `;
    artifactList.append(item);
  }

  tokenPreview.replaceChildren();

  const context = document.createElement("p");
  context.className = "token-context";
  context.textContent = showcase.tokenPreview.context;
  tokenPreview.append(context);

  const list = document.createElement("ul");
  list.className = "token-list";

  for (const entry of showcase.tokenPreview.entries) {
    const item = document.createElement("li");
    item.className = "token-row";
    item.innerHTML = `
      <div>
        <strong>${entry.token}</strong>
        <span>${entry.type}</span>
      </div>
      <div class="token-value">
        <strong>${entry.value}</strong>
        ${entry.detail ? `<span>${entry.detail}</span>` : ""}
      </div>
    `;
    list.append(item);
  }

  tokenPreview.append(list);
}
