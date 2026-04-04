import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const exampleRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(exampleRoot, "..", "..");

const resolver = join(repoRoot, "examples", "charter-steel", "charter-steel.resolver.json");
const generatedRoot = join(exampleRoot, "generated", "paint");
const packageDest = join(generatedRoot, "web");
const tokensDest = join(generatedRoot, "tokens.ts");

function run(command: string, args: string[], cwd: string) {
  const result = spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

async function replaceDirectory(source: string, destination: string) {
  await rm(destination, { recursive: true, force: true });
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, force: true });
}

async function replaceFile(source: string, destination: string) {
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, { force: true });
}

const tempRoot = await mkdtemp(join(tmpdir(), "paint-web-tokens-consumer-"));
const outDir = join(tempRoot, "paint");

run("bash", [join(repoRoot, "scripts", "ensure_premath_projection.sh")], repoRoot);
run(
  "cargo",
  ["run", "--", "build", resolver, "--out", outDir, "--target", "web-tokens-ts"],
  repoRoot,
);

await replaceFile(join(outDir, "tokens.ts"), tokensDest);
await replaceDirectory(join(outDir, "web"), packageDest);

console.log(`refreshed ${tokensDest}`);
console.log(`refreshed ${packageDest}`);
