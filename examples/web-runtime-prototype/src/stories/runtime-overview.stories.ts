import { buildStorybookOverviewModel } from "../model/storybook.ts";
import { applyArgsToElement, stylesheetHrefs } from "../runtime/web-runtime.ts";

const overview = buildStorybookOverviewModel("paint-button");
const showcase = overview.componentShowcase;
const component = showcase.component;

function textElement<TagName extends keyof HTMLElementTagNameMap>(
  tagName: TagName,
  className: string,
  text: string,
) {
  const element = document.createElement(tagName);
  element.className = className;
  element.textContent = text;
  return element;
}

function listItem(label: string, value: string) {
  const row = document.createElement("li");
  row.className = "paint-storybook-list-item";

  const labelElement = document.createElement("span");
  labelElement.className = "paint-storybook-list-label";
  labelElement.textContent = label;

  const valueElement = document.createElement("span");
  valueElement.className = "paint-storybook-list-value";
  valueElement.textContent = value;

  row.append(labelElement, valueElement);
  return row;
}

function createSection(title: string, description: string) {
  const section = document.createElement("section");
  section.className = "paint-storybook-section";
  section.append(
    textElement("h2", "paint-storybook-section-title", title),
    textElement("p", "paint-storybook-section-copy", description),
  );
  return section;
}

function renderExampleCard(example: (typeof showcase.examples)[number]) {
  const card = document.createElement("article");
  card.className = "paint-storybook-card";

  const header = document.createElement("div");
  header.className = "paint-storybook-card-header";
  header.append(
    textElement("h3", "paint-storybook-card-title", example.label),
    textElement("p", "paint-storybook-card-copy", example.context),
  );

  const preview = document.createElement("div");
  preview.className = "paint-storybook-preview";
  const element = document.createElement(component.tagName);
  preview.append(applyArgsToElement(element, component, example.args));

  const inputs = document.createElement("ul");
  inputs.className = "paint-storybook-list";
  for (const input of example.inputs) {
    inputs.append(listItem(input.label, input.value));
  }

  card.append(header, preview, inputs);
  return card;
}

function renderTokenPreview() {
  const list = document.createElement("ul");
  list.className = "paint-storybook-list";
  for (const entry of showcase.tokenPreview.entries) {
    list.append(listItem(entry.token, entry.value));
  }
  return list;
}

function renderArtifactList() {
  const list = document.createElement("ul");
  list.className = "paint-storybook-list";
  for (const artifact of showcase.artifacts) {
    list.append(
      listItem(
        `${artifact.label} (${artifact.backendId})`,
        artifact.file,
      ),
    );
  }
  return list;
}

function renderFindings() {
  const container = document.createElement("div");
  container.className = "paint-storybook-findings";

  const lead = document.createElement("p");
  lead.className = "paint-storybook-section-copy";
  lead.textContent = overview.findings.isClean
    ? "This generated prototype currently verifies cleanly across its tracked backend reports."
    : `This generated prototype currently has ${overview.findings.total} open finding(s).`;
  container.append(lead);

  const reports = document.createElement("ul");
  reports.className = "paint-storybook-list";
  for (const report of overview.findings.reports) {
    reports.append(
      listItem(
        `${report.backendId} (${report.reportKind})`,
        `${report.total} finding(s) in ${report.artifact}`,
      ),
    );
  }
  container.append(reports);

  if (overview.findings.byKind.length > 0) {
    const byKind = document.createElement("ul");
    byKind.className = "paint-storybook-list";
    for (const entry of overview.findings.byKind) {
      byKind.append(listItem(entry.kind, String(entry.count)));
    }
    container.append(byKind);
  }

  const firstFinding = overview.findings.reports.flatMap((report) => report.findings)[0];
  if (firstFinding) {
    const findingCard = document.createElement("article");
    findingCard.className = "paint-storybook-card paint-storybook-card-inline";
    findingCard.append(
      textElement("h3", "paint-storybook-card-title", firstFinding.family),
      textElement("p", "paint-storybook-card-copy", firstFinding.message),
      textElement(
        "p",
        "paint-storybook-card-copy",
        `${firstFinding.kind} · ${firstFinding.severity}${firstFinding.location ? ` · ${firstFinding.location}` : ""}`,
      ),
    );
    container.append(findingCard);
  }

  return container;
}

function renderSourceList() {
  const list = document.createElement("ul");
  list.className = "paint-storybook-list";
  for (const source of overview.system.sources) {
    list.append(
      listItem(
        `${source.id} (${source.toolName} ${source.toolVersion})`,
        `${source.packId}@${source.packVersion} · ${source.manifest}`,
      ),
    );
  }
  return list;
}

function storybookStyles() {
  return `
    .paint-storybook {
      box-sizing: border-box;
      color: #f4f6fb;
      background:
        radial-gradient(circle at top right, rgba(52, 87, 174, 0.25), transparent 26rem),
        linear-gradient(180deg, #0d1324 0%, #10182d 100%);
      min-height: 100vh;
      padding: 2rem;
      font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    }

    .paint-storybook-shell {
      margin: 0 auto;
      max-width: 74rem;
      display: grid;
      gap: 1.25rem;
    }

    .paint-storybook-hero,
    .paint-storybook-section,
    .paint-storybook-card {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 1rem;
      padding: 1.25rem;
      box-shadow: 0 18px 40px rgba(2, 6, 23, 0.28);
    }

    .paint-storybook-eyebrow {
      color: #8cb0ff;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      margin: 0 0 0.6rem;
      text-transform: uppercase;
    }

    .paint-storybook-title {
      font-size: clamp(2.1rem, 3vw, 3.3rem);
      line-height: 1.05;
      margin: 0;
    }

    .paint-storybook-copy,
    .paint-storybook-section-copy,
    .paint-storybook-card-copy {
      color: #c6d2eb;
      line-height: 1.55;
      margin: 0.6rem 0 0;
    }

    .paint-storybook-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
    }

    .paint-storybook-section-title,
    .paint-storybook-card-title {
      font-size: 1.05rem;
      margin: 0;
    }

    .paint-storybook-preview {
      margin-top: 1rem;
      padding: 1rem;
      border-radius: 0.85rem;
      background: rgba(15, 23, 42, 0.55);
      border: 1px solid rgba(148, 163, 184, 0.12);
    }

    .paint-storybook-list {
      display: grid;
      gap: 0.5rem;
      list-style: none;
      margin: 1rem 0 0;
      padding: 0;
    }

    .paint-storybook-list-item {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.7rem 0.85rem;
      border-radius: 0.8rem;
      background: rgba(30, 41, 59, 0.64);
    }

    .paint-storybook-list-label {
      color: #eef2ff;
      font-weight: 600;
    }

    .paint-storybook-list-value {
      color: #c6d2eb;
      text-align: right;
    }

    .paint-storybook-card-header {
      display: grid;
      gap: 0.25rem;
    }

    .paint-storybook-card-inline {
      margin-top: 1rem;
    }
  `;
}

export function renderRuntimeOverview() {
  const root = document.createElement("div");
  root.className = "paint-storybook";

  const style = document.createElement("style");
  style.textContent = storybookStyles();

  const shell = document.createElement("div");
  shell.className = "paint-storybook-shell";

  const hero = document.createElement("section");
  hero.className = "paint-storybook-hero";
  hero.append(
    textElement("p", "paint-storybook-eyebrow", "Storybook consumer workspace"),
    textElement("h1", "paint-storybook-title", overview.system.title),
    textElement(
      "p",
      "paint-storybook-copy",
      `${showcase.lede} Release ${overview.system.release} reads shared runtime records instead of inventing Storybook-owned truth.`,
    ),
  );

  const sources = createSection(
    "Generated sources",
    "Storybook stays above generated Paint artifacts and the shared web runtime IR.",
  );
  sources.append(renderSourceList());

  const examples = createSection(
    "Component examples",
    showcase.summary,
  );
  const exampleGrid = document.createElement("div");
  exampleGrid.className = "paint-storybook-grid";
  for (const example of showcase.examples) {
    exampleGrid.append(renderExampleCard(example));
  }
  examples.append(exampleGrid);

  const artifacts = createSection(
    "Artifact bindings",
    "These are the concrete backend outputs this consumer depends on.",
  );
  artifacts.append(renderArtifactList());

  const findings = createSection(
    "Build health",
    "Verification stays legible in the workspace through machine-readable report artifacts.",
  );
  findings.append(renderFindings());

  const tokens = createSection(
    "Preview tokens",
    `A small token slice from ${showcase.tokenPreview.context} keeps the runtime surface tied back to generated token data.`,
  );
  tokens.append(renderTokenPreview());

  shell.append(hero, sources, examples, artifacts, findings, tokens);
  root.append(style, shell);
  return root;
}

const meta = {
  title: "Overview/Runtime Workspace",
  tags: ["autodocs"],
  parameters: {
    layout: "fullscreen",
    docs: {
      description: {
        component:
          "A real Storybook/docs consumer over the shared web runtime IR, generated backend artifacts, and machine-readable verification reports.",
      },
    },
    paintRuntime: {
      componentId: component.id,
      requiredStylesheets: stylesheetHrefs(component),
    },
  },
};

export default meta;

export const RuntimeOverview = {
  render: renderRuntimeOverview,
};
