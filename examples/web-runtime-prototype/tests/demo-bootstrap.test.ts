import { beforeEach, describe, expect, test } from "bun:test";
import { bootDemoHost } from "../demo/boot.ts";
import { startDemo } from "../demo/main.ts";

function installDemoShell() {
  document.body.innerHTML = `
    <main>
      <section>
        <h1 id="demo-title">Loading...</h1>
        <p id="demo-lede"></p>
        <p id="demo-status">Waiting for browser host bootstrap…</p>
      </section>
      <section>
        <p id="demo-summary"></p>
        <div id="demo-grid"></div>
      </section>
      <section>
        <ul id="artifact-list"></ul>
      </section>
      <section>
        <pre id="token-preview"></pre>
      </section>
      <section id="boot-error" hidden>
        <p id="boot-error-message"></p>
        <pre id="boot-error-stack"></pre>
      </section>
    </main>
  `;
}

beforeEach(() => {
  installDemoShell();
});

describe("demo bootstrap", () => {
  test("boots the real demo runtime into the shell", async () => {
    const result = await bootDemoHost(document, async () => ({ startDemo }));

    expect(result.ok).toBe(true);
    expect(document.body.dataset.demoState).toBe("ready");
    expect(document.getElementById("demo-title")?.textContent).toBe("Paint Web Runtime Prototype");
    expect(document.getElementById("demo-grid")?.children.length).toBe(3);
    expect(document.getElementById("artifact-list")?.children.length).toBe(2);
    expect(document.getElementById("boot-error")?.hasAttribute("hidden")).toBe(true);
  });

  test("surfaces importer failures in-page instead of leaving the shell stuck", async () => {
    const result = await bootDemoHost(document, async () => {
      throw new Error("simulated bootstrap failure");
    });

    expect(result.ok).toBe(false);
    expect(document.body.dataset.demoState).toBe("error");
    expect(document.getElementById("demo-title")?.textContent).toBe("Demo failed to boot");
    expect(document.getElementById("demo-status")?.textContent).toBe("Browser host failed.");
    expect(document.getElementById("boot-error")?.hasAttribute("hidden")).toBe(false);
    expect(document.getElementById("boot-error-message")?.textContent).toContain(
      "simulated bootstrap failure",
    );
  });
});
