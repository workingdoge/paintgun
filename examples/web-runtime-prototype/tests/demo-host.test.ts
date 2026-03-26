import { afterEach, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { startDemoServer } from "../scripts/serve-demo.ts";

const exampleRoot = resolve(import.meta.dir, "..");

let activeServer: ReturnType<typeof startDemoServer> | null = null;

afterEach(() => {
  activeServer?.stop(true);
  activeServer = null;
});

describe("browser demo host", () => {
  test("serves the demo page and bundled entrypoint", async () => {
    activeServer = startDemoServer(0);

    const indexResponse = await fetch(new URL("/demo/index.html", activeServer.url));
    const indexHtml = await indexResponse.text();
    expect(indexResponse.status).toBe(200);
    expect(indexHtml).toContain("./dist/main.js");
    expect(indexHtml).toContain("../generated/paint/css/tokens.vars.css");

    const bundleResponse = await fetch(new URL("/demo/dist/main.js", activeServer.url));
    const bundleBody = await bundleResponse.text();
    expect(bundleResponse.status).toBe(200);
    expect(bundleBody).toContain("paint-button");

    const cssResponse = await fetch(
      new URL("/generated/paint/css/tokens.vars.css", activeServer.url),
    );
    expect(cssResponse.status).toBe(200);
  });

  test("keeps the demo page aligned with the built bundle name", async () => {
    const html = await readFile(join(exampleRoot, "demo", "index.html"), "utf8");
    expect(html).toContain("./dist/main.js");
  });
});
