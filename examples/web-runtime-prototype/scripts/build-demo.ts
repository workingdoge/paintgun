import { build } from "esbuild";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const exampleRoot = resolve(import.meta.dir, "..");
const outdir = join(exampleRoot, "demo", "dist");

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

await build({
  entryPoints: [join(exampleRoot, "demo", "boot.ts"), join(exampleRoot, "demo", "main.ts")],
  outdir,
  bundle: true,
  platform: "browser",
  format: "esm",
  target: ["es2018"],
  sourcemap: true,
  logLevel: "info",
});
