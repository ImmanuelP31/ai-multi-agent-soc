import { createReadStream, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const host = "0.0.0.0";
const port = Number.parseInt(process.env.PORT || "4173", 10);
const dist = fileURLToPath(new URL("./dist", import.meta.url));

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

function sendFile(response, filePath) {
  response.writeHead(200, {
    "Cache-Control": filePath.endsWith("index.html")
      ? "no-cache"
      : "public, max-age=31536000, immutable",
    "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream",
  });
  createReadStream(filePath).pipe(response);
}

createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ status: "ready" }));
    return;
  }

  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const candidate = resolve(dist, `.${pathname}`);
  if (!candidate.startsWith(`${dist}/`)) {
    response.writeHead(400);
    response.end("Bad request");
    return;
  }

  try {
    if (statSync(candidate).isFile()) {
      sendFile(response, candidate);
      return;
    }
  } catch {
    // The React application handles client-side routes through index.html.
  }
  sendFile(response, resolve(dist, "index.html"));
}).listen(port, host, () => {
  console.log(`SOC frontend listening on http://${host}:${port}`);
});
