import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve } from "node:path";
import { createServer } from "node:http";

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".cjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8"
};

function readArg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) {
    return fallback;
  }
  return process.argv[index + 1] ?? fallback;
}

const host = readArg("host", "127.0.0.1");
const port = Number(readArg("port", "4173"));
const rootDir = process.cwd();

function safeResolve(pathname) {
  const cleaned = pathname.split("?")[0].split("#")[0];
  const normalized = normalize(decodeURIComponent(cleaned)).replace(/^(\.\.[/\\])+/, "");
  return resolve(rootDir, join(".", normalized));
}

const server = createServer((req, res) => {
  const method = req.method ?? "GET";
  if (method !== "GET" && method !== "HEAD") {
    res.statusCode = 405;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Method Not Allowed");
    return;
  }

  const pathname = req.url ?? "/";

  if (pathname === "/health") {
    res.statusCode = 200;
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  const targetPath = safeResolve(pathname === "/" ? "/e2e/fixtures/index.html" : pathname);
  if (!targetPath.startsWith(rootDir)) {
    res.statusCode = 403;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Forbidden");
    return;
  }

  if (!existsSync(targetPath)) {
    res.statusCode = 404;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Not Found");
    return;
  }

  const stats = statSync(targetPath);
  if (stats.isDirectory()) {
    res.statusCode = 404;
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end("Not Found");
    return;
  }

  const contentType = mimeTypes[extname(targetPath)] ?? "application/octet-stream";
  res.statusCode = 200;
  res.setHeader("content-type", contentType);
  res.setHeader("cache-control", "no-store");

  if (method === "HEAD") {
    res.end();
    return;
  }

  createReadStream(targetPath).pipe(res);
});

server.listen(port, host, () => {
  process.stdout.write(`E2E server running at http://${host}:${port}\n`);
});
