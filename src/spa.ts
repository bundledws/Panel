import http from "node:http";
import fs from "node:fs";
import path from "node:path";

const HTML_PATH = path.join(path.dirname(new URL(import.meta.url).pathname), "spa.html");

// Cache the HTML in memory at startup — avoids readFileSync on every page load
const HTML = fs.readFileSync(HTML_PATH, "utf8");

export async function serveHtml(req: http.IncomingMessage, res: http.ServerResponse) {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(HTML);
}