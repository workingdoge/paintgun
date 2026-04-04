import { existsSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";

const exampleRoot = resolve(import.meta.dir, "..");
const bridgeMountPath = "/bridge/";
const bridgeBundle = join(exampleRoot, "bridge", "dist", "main.js");

const mimeTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".ts", "text/plain; charset=utf-8"],
]);

export function startBridgeServer(port = 0) {
  if (!existsSync(bridgeBundle)) {
    throw new Error("bridge bundle is missing; run `bun run build` first");
  }

  return Bun.serve({
    port,
    fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/" || url.pathname === "/bridge") {
        return Response.redirect(new URL(bridgeMountPath, url), 302);
      }

      const pathname =
        url.pathname === bridgeMountPath
          ? "/bridge/index.html"
          : url.pathname === "/favicon.ico"
            ? "/bridge/favicon.svg"
            : url.pathname;

      const safeRelative = normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
      const filePath = join(exampleRoot, safeRelative);
      const file = Bun.file(filePath);

      if (!existsSync(filePath)) {
        return new Response("Not found", { status: 404 });
      }

      return new Response(file, {
        headers: {
          "content-type": mimeTypes.get(extname(filePath)) ?? "application/octet-stream",
        },
      });
    },
  });
}

if (import.meta.main) {
  const server = startBridgeServer(Number(Bun.env.PORT ?? "3001"));
  console.log(`Paint design-tool bridge running at ${new URL(bridgeMountPath, server.url)}`);
}
