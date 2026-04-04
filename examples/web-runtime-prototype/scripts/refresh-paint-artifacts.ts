import { $ } from "bun";
import { cp, mkdtemp, mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const exampleRoot = resolve(import.meta.dir, "..");
const repoRoot = resolve(exampleRoot, "..", "..");

const resolver = join(repoRoot, "examples/charter-steel/charter-steel.resolver.json");
const policy = join(repoRoot, "examples/charter-steel/policy.json");
const contracts = join(exampleRoot, "component-contracts.json");

const paintGeneratedRoot = join(exampleRoot, "generated", "paint");
const cssDest = join(paintGeneratedRoot, "css");
const webDest = join(paintGeneratedRoot, "web");

await $`"${join(repoRoot, "scripts", "ensure_premath_projection.sh")}"`.cwd(repoRoot).quiet();

async function rebuildTarget(outDir: string, target: string, withContracts: boolean) {
  const command = [
    "cargo",
    "run",
    "--",
    "build",
    resolver,
    "--out",
    outDir,
    "--target",
    target,
    "--policy",
    policy,
    "--format",
    "json",
  ];

  if (withContracts) {
    command.push("--contracts", contracts);
  }

  await $`${command}`.cwd(repoRoot).quiet();
}

async function replaceDirectory(source: string, destination: string) {
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: true });
  await cp(source, destination, { recursive: true, force: true });
}

const tempRoot = await mkdtemp(join(tmpdir(), "paint-web-runtime-"));
const cssOut = join(tempRoot, "css");
const webOut = join(tempRoot, "web");

await rebuildTarget(cssOut, "web-css-vars", true);
await rebuildTarget(webOut, "web-tokens-ts", false);
await replaceDirectory(cssOut, cssDest);
await replaceDirectory(webOut, webDest);

console.log(`refreshed ${cssDest}`);
console.log(`refreshed ${webDest}`);
