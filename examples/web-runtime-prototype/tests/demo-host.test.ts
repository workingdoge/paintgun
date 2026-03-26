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
  test("mounts the demo at /demo/ and keeps relative imports aligned with that base", async () => {
    activeServer = startDemoServer(0);

    const rootResponse = await fetch(new URL("/", activeServer.url), {
      redirect: "manual",
    });
    expect(rootResponse.status).toBe(302);
    expect(rootResponse.headers.get("location")?.endsWith("/demo/")).toBe(true);

    const demoResponse = await fetch(new URL("/demo", activeServer.url), {
      redirect: "manual",
    });
    expect(demoResponse.status).toBe(302);
    expect(demoResponse.headers.get("location")?.endsWith("/demo/")).toBe(true);

    const indexResponse = await fetch(new URL("/demo/", activeServer.url));
    const indexHtml = await indexResponse.text();
    expect(indexResponse.status).toBe(200);
    expect(indexResponse.url.endsWith("/demo/")).toBe(true);
    expect(indexHtml).toContain("./dist/boot.js");
    expect(indexHtml).toContain("boot-error");
    expect(indexHtml).toContain("../generated/paint/css/tokens.vars.css");
    expect(new URL("./dist/boot.js", indexResponse.url).pathname).toBe("/demo/dist/boot.js");
    expect(new URL("../generated/paint/css/tokens.vars.css", indexResponse.url).pathname).toBe(
      "/generated/paint/css/tokens.vars.css",
    );

    const bootResponse = await fetch(new URL("/demo/dist/boot.js", activeServer.url));
    const bootBundle = await bootResponse.text();
    expect(bootResponse.status).toBe(200);
    expect(bootBundle).toContain("bootDemoHost");

    const mainResponse = await fetch(new URL("/demo/dist/main.js", activeServer.url));
    const mainBundle = await mainResponse.text();
    expect(mainResponse.status).toBe(200);
    expect(mainBundle).toContain("paint-button");

    const cssResponse = await fetch(
      new URL("/generated/paint/css/tokens.vars.css", activeServer.url),
    );
    expect(cssResponse.status).toBe(200);

    const faviconResponse = await fetch(new URL("/favicon.ico", activeServer.url));
    expect(faviconResponse.status).toBe(200);
  });

  test("keeps the demo page aligned with the built bundle name", async () => {
    const html = await readFile(join(exampleRoot, "demo", "index.html"), "utf8");
    expect(html).toContain("./dist/boot.js");
  });

  test("builds the browser bundles to a conservative syntax baseline", async () => {
    const bootBundle = await readFile(join(exampleRoot, "demo", "dist", "boot.js"), "utf8");
    const mainBundle = await readFile(join(exampleRoot, "demo", "dist", "main.js"), "utf8");

    for (const bundle of [bootBundle, mainBundle]) {
      expect(bundle.includes("#shadow")).toBe(false);
      expect(bundle.includes("shadowRootRef;")).toBe(false);
      expect(bundle.includes("?.")).toBe(false);
      expect(bundle.includes("??")).toBe(false);
      expect(bundle.includes("import.meta")).toBe(false);
    }
  });
});
