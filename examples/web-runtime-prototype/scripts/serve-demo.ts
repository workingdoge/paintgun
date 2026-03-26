import { existsSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";

const exampleRoot = resolve(import.meta.dir, "..");
const demoMountPath = "/demo/";
const demoBundle = join(exampleRoot, "demo", "dist", "main.js");

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".ts", "text/plain; charset=utf-8"],
  [".txt", "text/plain; charset=utf-8"],
]);

export function startDemoServer(port = 0) {
  if (!existsSync(demoBundle)) {
    throw new Error("demo bundle is missing; run `bun run build:demo` first");
  }

  return Bun.serve({
    port,
    fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/" || url.pathname === "/demo") {
        return Response.redirect(new URL(demoMountPath, url), 302);
      }

      const pathname =
        url.pathname === demoMountPath
          ? "/demo/index.html"
          : url.pathname === "/favicon.ico"
            ? "/demo/favicon.svg"
            : url.pathname;
      const safeRelative = normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
      const filePath = join(exampleRoot, safeRelative);
      const file = Bun.file(filePath);

      if (!existsSync(filePath)) {
        return new Response("Not found", { status: 404 });
      }

      const ext = extname(filePath);
      return new Response(file, {
        headers: {
          "content-type": mimeTypes.get(ext) ?? "application/octet-stream",
        },
      });
    },
  });
}

if (import.meta.main) {
  const server = startDemoServer(Number(Bun.env.PORT ?? "3000"));
  console.log(`Paint demo host running at ${new URL(demoMountPath, server.url)}`);
}
