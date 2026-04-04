import { buildDesignToolBridgeModel } from "./model/bridge.ts";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderBridgeApp(selectedComponentId?: string): string {
  const model = buildDesignToolBridgeModel(selectedComponentId);

  const componentButtons = model.componentList
    .map(
      (component) => `
        <button type="button" data-component-id="${escapeHtml(component.id)}" aria-current="${component.id === model.selectedComponent.id}">
          <span class="nav-title">${escapeHtml(component.title)}</span>
          <span class="nav-meta">${escapeHtml(component.description)}</span>
          <span class="pill-row">
            <span class="pill">${escapeHtml(component.status)}</span>
            <span class="pill">${component.exampleCount} example${component.exampleCount === 1 ? "" : "s"}</span>
            <span class="pill">${component.clean ? "Clean" : `${component.findingCount} finding${component.findingCount === 1 ? "" : "s"}`}</span>
          </span>
        </button>
      `,
    )
    .join("");

  const sourceCards = model.sources
    .map(
      (source) => `
        <article class="source-card">
          <p class="card-kicker">${escapeHtml(source.label)} source</p>
          <h3 class="card-title">${escapeHtml(source.pack)}</h3>
          <p class="card-copy">${escapeHtml(source.toolVersion)} on DTCG ${escapeHtml(source.spec)}</p>
          <div class="pill-row">
            <span class="pill">${source.clean ? "Verification clean" : `${source.findingCount} finding${source.findingCount === 1 ? "" : "s"}`}</span>
            <span class="pill">${source.artifactCount} artifact${source.artifactCount === 1 ? "" : "s"}</span>
          </div>
          <div class="fact-grid">
            <div class="fact">
              <span class="fact-label">Manifest</span>
              <span class="fact-value mono">${escapeHtml(source.manifest)}</span>
            </div>
            <div class="fact">
              <span class="fact-label">Diagnostics</span>
              <span class="fact-value mono">${escapeHtml(source.diagnostics)}</span>
            </div>
            <div class="fact">
              <span class="fact-label">Content hash</span>
              <span class="fact-value mono">${escapeHtml(source.packHash)}</span>
            </div>
          </div>
        </article>
      `,
    )
    .join("");

  const exampleCards = model.selectedComponent.examples
    .map(
      (example) => `
        <article class="example-card">
          <p class="card-kicker">${escapeHtml(example.context)}</p>
          <h3 class="card-title">${escapeHtml(example.label)}</h3>
          <p class="card-copy">Rendered copy: <strong>${escapeHtml(example.contentLabel)}</strong></p>
          <div class="pill-row">
            ${example.inputs.map((input) => `<span class="pill">${escapeHtml(input)}</span>`).join("")}
          </div>
          <div class="token-grid">
            ${example.tokenPreview
              .map(
                (token) => `
                  <div class="token-chip">
                    ${token.swatch ? `<div class="token-swatch" style="background:${escapeHtml(token.swatch)}"></div>` : ""}
                    <div class="token-label">${escapeHtml(token.label)}</div>
                    <div class="token-value mono">${escapeHtml(token.value)}</div>
                  </div>
                `,
              )
              .join("")}
          </div>
        </article>
      `,
    )
    .join("");

  const artifactCards = model.selectedComponent.artifactGroups
    .map(
      (group) => `
        <article class="artifact-card">
          <p class="card-kicker">${escapeHtml(group.backendId)}</p>
          <h3 class="card-title">${group.artifacts.length} shared artifact${group.artifacts.length === 1 ? "" : "s"}</h3>
          <div class="stack">
            ${group.artifacts
              .map(
                (artifact) => `
                  <div class="fact">
                    <span class="fact-label">${escapeHtml(artifact.kind)}</span>
                    <span class="fact-value mono">${escapeHtml(artifact.file)}</span>
                    <span class="card-copy">${escapeHtml(artifact.size)}${artifact.apiVersion ? ` - ${escapeHtml(artifact.apiVersion)}` : ""}</span>
                  </div>
                `,
              )
              .join("")}
          </div>
        </article>
      `,
    )
    .join("");

  const verificationCards = model.verificationReports
    .map(
      (report) => `
        <article class="artifact-card">
          <p class="card-kicker">${escapeHtml(report.sourceId)} diagnostics</p>
          <h3 class="card-title">${report.clean ? "Clean" : `${report.findingCount} findings`}</h3>
          <p class="card-copy">${escapeHtml(report.backendIds.join(", "))}</p>
          <div class="fact-grid">
            <div class="fact">
              <span class="fact-label">Projection</span>
              <span class="fact-value mono">${escapeHtml(report.reportFile)}</span>
            </div>
            <div class="fact">
              <span class="fact-label">Source report</span>
              <span class="fact-value mono">${escapeHtml(report.sourceReportFile)}</span>
            </div>
            <div class="fact">
              <span class="fact-label">Families</span>
              <span class="fact-value">${escapeHtml(report.families.join(", "))}</span>
            </div>
          </div>
        </article>
      `,
    )
    .join("");

  return `
    <main class="shell">
      <p class="eyebrow">Paint Design-Tool Bridge</p>
      <section class="hero">
        <article class="hero-card">
          <h1 class="title">${escapeHtml(model.system.title)}</h1>
          <p class="lede">${escapeHtml(model.system.summary)}</p>
          <div class="badge-row">
            ${model.system.badges
              .map((badge, index) => `<span class="badge ${index === 0 ? "success" : ""}">${escapeHtml(badge)}</span>`)
              .join("")}
          </div>
        </article>
        <aside class="hero-card">
          <p class="section-title">Release ${escapeHtml(model.system.release)}</p>
          <div class="metric-row">
            ${model.system.metrics
              .map(
                (metric) => `
                  <div class="metric">
                    <span class="metric-label">${escapeHtml(metric.label)}</span>
                    <span class="metric-value">${escapeHtml(metric.value)}</span>
                  </div>
                `,
              )
              .join("")}
          </div>
        </aside>
      </section>

      <section class="workspace">
        <nav class="nav panel" aria-label="Catalog components">
          <p class="section-title">Component catalog</p>
          ${componentButtons}
        </nav>

        <section class="content">
          <article class="panel">
            <p class="section-title">Selected component</p>
            <h2 class="section-heading">${escapeHtml(model.selectedComponent.title)}</h2>
            <p class="section-copy">${escapeHtml(model.selectedComponent.description)}</p>
            <div class="badge-row">
              <span class="badge success">${model.selectedComponent.findings.clean ? "Verification clean" : `${model.selectedComponent.findings.total} findings`}</span>
              <span class="badge">${escapeHtml(model.selectedComponent.status)}</span>
              <span class="badge">Contract ${escapeHtml(model.selectedComponent.compatibilityLabel)}</span>
            </div>
            <div class="fact-grid">
              <div class="fact">
                <span class="fact-label">Accessibility</span>
                <span class="fact-value">${escapeHtml(model.selectedComponent.accessibilityNotes.join(" "))}</span>
              </div>
              <div class="fact">
                <span class="fact-label">Parts</span>
                <span class="fact-value">${escapeHtml(model.selectedComponent.parts.join(" | "))}</span>
              </div>
              <div class="fact">
                <span class="fact-label">Slots</span>
                <span class="fact-value">${escapeHtml(model.selectedComponent.slots.join(" | "))}</span>
              </div>
              <div class="fact">
                <span class="fact-label">Token-role bindings</span>
                <span class="fact-value">${escapeHtml(model.selectedComponent.tokenRoleNote)}</span>
              </div>
            </div>
            <div class="pill-row">
              ${model.selectedComponent.inputs.map((input) => `<span class="pill">${escapeHtml(input)}</span>`).join("")}
            </div>
          </article>

          <article class="panel">
            <p class="section-title">Examples and token previews</p>
            <div class="example-grid">${exampleCards}</div>
          </article>

          <article class="panel">
            <p class="section-title">Artifact evidence</p>
            <div class="artifact-grid">${artifactCards}</div>
          </article>

          <article class="panel">
            <p class="section-title">Verification and provenance</p>
            <div class="artifact-grid">${verificationCards}</div>
            <div class="source-list">${sourceCards}</div>
          </article>
        </section>
      </section>
    </main>
  `;
}

export function mountDesignToolBridge(root: HTMLElement): void {
  let selectedComponentId: string | undefined;

  const render = () => {
    root.innerHTML = renderBridgeApp(selectedComponentId);
    [...root.getElementsByTagName("button")]
      .filter((button) => Boolean(button.dataset.componentId))
      .forEach((button) => {
        button.addEventListener("click", () => {
          selectedComponentId = button.dataset.componentId;
          render();
        });
      });
  };

  render();
}

const root =
  typeof document !== "undefined"
    ? document.getElementById("app")
    : null;

if (typeof HTMLElement !== "undefined" && root instanceof HTMLElement) {
  mountDesignToolBridge(root);
}
