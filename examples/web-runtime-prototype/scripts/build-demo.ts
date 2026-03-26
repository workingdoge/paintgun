import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const exampleRoot = resolve(import.meta.dir, "..");
const outdir = join(exampleRoot, "demo", "dist");

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

const result = await Bun.build({
  entrypoints: [join(exampleRoot, "demo", "main.ts")],
  outdir,
  target: "browser",
  format: "esm",
  minify: false,
  sourcemap: "external",
});

if (!result.success) {
  for (const log of result.logs) {
    console.error(log);
  }
  throw new Error("failed to build demo bundle");
}

for (const output of result.outputs) {
  console.log(`built ${output.path}`);
}
