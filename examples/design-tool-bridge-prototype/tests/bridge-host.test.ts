import { afterEach, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { startBridgeServer } from "../scripts/serve-bridge.ts";

const exampleRoot = resolve(import.meta.dir, "..");

let activeServer: ReturnType<typeof startBridgeServer> | null = null;

afterEach(() => {
  activeServer?.stop(true);
  activeServer = null;
});

test("bridge host mounts at /bridge/ and serves the bundled app", async () => {
  activeServer = startBridgeServer(0);

  const rootResponse = await fetch(new URL("/", activeServer.url), { redirect: "manual" });
  expect(rootResponse.status).toBe(302);
  expect(rootResponse.headers.get("location")?.endsWith("/bridge/")).toBe(true);

  const bridgeResponse = await fetch(new URL("/bridge/", activeServer.url));
  const html = await bridgeResponse.text();
  expect(bridgeResponse.status).toBe(200);
  expect(bridgeResponse.url.endsWith("/bridge/")).toBe(true);
  expect(html).toContain("./dist/main.js");
  expect(html).toContain("Paint Design-Tool Bridge Prototype");
  expect(new URL("./dist/main.js", bridgeResponse.url).pathname).toBe("/bridge/dist/main.js");

  const bundleResponse = await fetch(new URL("/bridge/dist/main.js", activeServer.url));
  const bundle = await bundleResponse.text();
  expect(bundleResponse.status).toBe(200);
  expect(bundle).toContain("mountDesignToolBridge");

  const faviconResponse = await fetch(new URL("/favicon.ico", activeServer.url));
  expect(faviconResponse.status).toBe(200);
});

test("bridge bundle stays on the conservative browser baseline", async () => {
  const html = await readFile(join(exampleRoot, "bridge", "index.html"), "utf8");
  const bundle = await readFile(join(exampleRoot, "bridge", "dist", "main.js"), "utf8");

  expect(html).toContain("./dist/main.js");
  expect(bundle.includes("import.meta")).toBe(false);
  expect(bundle.includes("?.")).toBe(false);
  expect(bundle.includes("??")).toBe(false);
});
