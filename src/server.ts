import http from "node:http";
import fs from "node:fs";
import * as pathMod from "node:path";
import { execSync } from "node:child_process";
import { readIntEnv, getAppDir, createToken } from "./env.js";
import { ControlPlane, type SessionPrincipal } from "./control-plane.js";
import { serveHtml } from "./spa.js";
import { startApp, stopApp, restartWithRebuild, getAppStatus, getAppLogs, getLogsSince } from "./deploy.js";
import { parseMultipartBody } from "./upload.js";
import { runPipeline } from "./pipeline.js";
import { createBackupZip } from "./backup.js";
import { DomainManager } from "./domain-manager.js";
import { validateDomain, verifyDnsResolution, generateDnsInstructions, isPrivateIp } from "./domain-validate.js";
import { listConfiguredDomains } from "./nginx.js";
import { getDomain, getDomainByDomain, listDomains, getAuditLogs, getDnsVerifications, getAcmeOrder, getDomainStats } from "./domain-store.js";
import { renewCertificate, needsRenewal, isExpired, getBackoffDelay } from "./certificate.js";

const PORT = readIntEnv("PORT", 8080);
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_ACTIVITY_LOGS = 10000;

// Ring buffer for activity logs — O(1) per insert vs O(n) splice
const appActivityLogs: string[] = new Array(MAX_ACTIVITY_LOGS);
let logIndex = 0;
let logCount = 0;
function logActivity(msg: string) {
  const ts = new Date().toISOString().replace("T", " ").substring(0, 19);
  appActivityLogs[logIndex] = `[${ts}] ${msg}`;
  logIndex = (logIndex + 1) % MAX_ACTIVITY_LOGS;
  if (logCount < MAX_ACTIVITY_LOGS) logCount++;
}
function getActivityLogs(): string[] {
  if (logCount < MAX_ACTIVITY_LOGS) return appActivityLogs.slice(0, logCount);
  return [...appActivityLogs.slice(logIndex), ...appActivityLogs.slice(0, logIndex)];
}

const cp = new ControlPlane();

const rateBuckets = new Map<string, { tokens: number; lastRefill: number }>();
const RATE_LIMIT = { maxTokens: 30, refillMs: 60_000, refillRate: 15 };
// Periodically evict stale rate-limit entries to prevent memory leak
const RATE_BUCKET_TTL = 10 * 60 * 1000; // 10 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (bucket.tokens >= RATE_LIMIT.maxTokens && (now - bucket.lastRefill) > RATE_BUCKET_TTL) {
      rateBuckets.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b) { b = { tokens: RATE_LIMIT.maxTokens, lastRefill: now }; rateBuckets.set(ip, b); }
  const elapsed = now - b.lastRefill;
  const refill = Math.floor(elapsed / RATE_LIMIT.refillMs) * RATE_LIMIT.refillRate;
  if (refill > 0) { b.tokens = Math.min(RATE_LIMIT.maxTokens, b.tokens + refill); b.lastRefill = now; }
  if (b.tokens <= 0) return false;
  b.tokens--; return true;
}

function setCookie(res: http.ServerResponse, token: string, expiresAt: Date, secure = false) {
  const secureFlag = secure ? "; Secure" : "";
  res.setHeader("set-cookie", `bws_session=${token}; HttpOnly; SameSite=Lax; Path=/; Expires=${expiresAt.toUTCString()}${secureFlag}`);
}
function clearCookie(res: http.ServerResponse) {
  res.setHeader("set-cookie", "bws_session=; HttpOnly; SameSite=Lax; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
}
function isBehindHttpsProxy(req: http.IncomingMessage): boolean {
  return req.headers["x-forwarded-proto"] === "https";
}
function readToken(req: http.IncomingMessage): string | undefined {
  const m = req.headers.cookie?.match(/bws_session=([^;]+)/);
  return m?.[1];
}
function readCsrf(req: http.IncomingMessage): string | undefined {
  return req.headers["x-csrf-token"] as string | undefined;
}
function requireAuth(req: http.IncomingMessage): Promise<SessionPrincipal> {
  const token = readToken(req);
  if (!token) throw new Error("Unauthorized");
  return cp.authenticateSession(token);
}
function requireCsrf(req: http.IncomingMessage, p: SessionPrincipal) {
  const csrf = readCsrf(req);
  if (!csrf || csrf !== p.session.csrfToken) throw new Error("Invalid CSRF token");
}
function requireAdmin(p: SessionPrincipal) {
  if (p.user.role !== "admin") throw new Error("Forbidden");
}

function parseBody(req: http.IncomingMessage, maxSize = 1024 * 1024): Promise<any> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalLength = 0;
    req.on("data", (c: Buffer) => {
      totalLength += c.length;
      if (totalLength > maxSize) {
        req.destroy();
        resolve({ error: "Request body too large" });
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (req.destroyed) return resolve({});
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { resolve({}); }
    });
  });
}

function sendJson(res: http.ServerResponse, status: number, data: any) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(data));
}
function sendError(res: http.ServerResponse, status: number, msg: string) {
  sendJson(res, status, { error: msg });
}

function validateRepoUrl(url: string): void {
  if (!/^(https?:\/\/|git@)[a-zA-Z0-9._:/%-]+\.git$/.test(url)) throw new Error("Invalid repository URL");
}
function validateBranch(branch: string): void {
  if (!/^[a-zA-Z0-9._/-]+$/.test(branch)) throw new Error("Invalid branch name");
}
function validateEnvKey(key: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) throw new Error(`Invalid env key: ${key}`);
}

const DIST_DIR = pathMod.join(pathMod.dirname(new URL(import.meta.url).pathname), "..", "dist");

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse, path: string): boolean {
  if (!path.startsWith("/dist/")) return false;
  const filePath = pathMod.join(DIST_DIR, path.slice(6));
  if (!filePath.startsWith(DIST_DIR)) return false;
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return false;
  const ext = pathMod.extname(filePath).toLowerCase();
  const mimeTypes: Record<string, string> = {
    ".js": "application/javascript; charset=utf-8",
    ".js.map": "application/json; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".eot": "application/vnd.ms-fontobject",
  };
  const contentType = mimeTypes[ext] || "application/octet-stream";
  const file = fs.readFileSync(filePath);
  res.writeHead(200, { "content-type": contentType, "cache-control": "public, max-age=31536000" });
  res.end(file);
  return true;
}

// ============================================================
// Route definitions — type-safe dispatch map
// ============================================================
type RouteHandler = (req: http.IncomingMessage, res: http.ServerResponse, body: any, ip: string) => Promise<void>;
interface RouteDef {
  handler: RouteHandler;
  auth?: boolean;
  csrf?: boolean;
  rateLimit?: boolean;
}

const routes = new Map<string, RouteDef>();

function route(method: string, path: string, def: RouteDef) {
  routes.set(`${method}:${path}`, def);
}

// --- AUTH ---
route("GET", "/api/check-setup", {
  handler: async (req, res) => sendJson(res, 200, { setup: !(await cp.hasAdmin()) }),
});
route("POST", "/api/setup", {
  handler: async (req, res, body) => {
    if (await cp.hasAdmin()) return sendError(res, 400, "Already set up");
    const { email, password } = body;
    if (!email || !password || password.length < 8) return sendError(res, 400, "Email and password (min 8 chars) required");
    return sendJson(res, 200, { ok: true, user: await cp.setupAdmin(email, password) });
  },
});
route("POST", "/api/admin/customers", {
  auth: true, csrf: true,
  handler: async (req, res, body) => {
    const p = await requireAuth(req);
    requireAdmin(p);
    const { email, password } = body;
    if (!email || !password || password.length < 8) return sendError(res, 400, "Email and password (min 8 chars) required");
    const user = await cp.createCustomer(email, password);
    logActivity(`Customer account created: ${email}`);
    return sendJson(res, 200, { ok: true, user });
  },
});
route("POST", "/api/login", {
  rateLimit: true,
  handler: async (req, res, body) => {
    const { email, password } = body;
    if (!email || !password) return sendError(res, 400, "Email and password required");
    const session = await cp.login(email, password);
    setCookie(res, session.sessionToken, session.expiresAt, isBehindHttpsProxy(req));
    return sendJson(res, 200, { user: session.user, csrfToken: session.csrfToken });
  },
});
route("POST", "/api/logout", {
  auth: true, csrf: true,
  handler: async (req, res) => {
    const token = readToken(req);
    if (token) await cp.logout(token);
    clearCookie(res);
    return sendJson(res, 200, { ok: true });
  },
});
route("GET", "/api/me", {
  auth: true,
  handler: async (req, res) => {
    const p = await requireAuth(req);
    return sendJson(res, 200, { user: p.user, csrfToken: p.session.csrfToken });
  },
});

// --- LOG DOWNLOAD ---
route("GET", "/api/app/logs/download", {
  auth: true,
  handler: async (req, res) => {
    const logs = await getLogsSince(24);
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "content-disposition": "attachment; filename=\"Logs.txt\"", "cache-control": "no-store" });
    res.end(logs || "No logs available for the last 24 hours.");
  },
});

// --- BACKUP DOWNLOAD ---
route("GET", "/api/app/backup", {
  auth: true,
  handler: async (req, res) => {
    const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
    const appDir = `/home/${userName}/Myapp`;
    if (!fs.existsSync(appDir)) {
      return sendError(res, 400, "Application directory not found. Deploy your app first.");
    }
    const tmpPath = `/tmp/bundledws-backup-${Date.now()}.zip`;
    try {
      await createBackupZip(appDir, tmpPath, ["node_modules", ".next", ".env", ".pm2", ".env.development.local", ".env.local",]);
      const data = fs.readFileSync(tmpPath);
      res.writeHead(200, {
        "content-type": "application/zip",
        "content-disposition": "attachment; filename=\"Myapp-backup.zip\"",
        "content-length": String(data.length),
        "cache-control": "no-store"
      });
      res.end(data);
    } catch (err: any) {
      return sendError(res, 500, `Backup failed: ${err.message}`);
    } finally {
      try { fs.unlinkSync(tmpPath); } catch {}
    }
  },
});

// --- DEPLOY GIT ---
route("POST", "/api/deploy/git", {
  auth: true, csrf: true, rateLimit: true,
  handler: async (req, res, body) => {
    const { repoUrl, branch } = body;
    if (!repoUrl) return sendError(res, 400, "repoUrl required");
    validateRepoUrl(repoUrl);
    const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
    const workspaceDir = `/home/${userName}/Myapp`;
    const logLines: string[] = [];
    const onLog = (line: string) => { logLines.push(line); logActivity(line); };
    logActivity(`Deployment started from git: ${repoUrl}`);
    onLog(`Starting deployment for ${repoUrl}`);
    onLog(`Workspace: ${workspaceDir}`);
    const result = await runPipeline({ workspaceDir, repoUrl, branch: branch || "main", logs: logLines, onLog });
    logActivity(`Deployment ${result.success ? "succeeded" : "failed"}: ${repoUrl} (stage: ${result.stage})`);
    return sendJson(res, result.success ? 200 : 400, { ...result, workspaceDir, logs: logLines });
  },
});

// --- DEPLOY ZIP ---
route("POST", "/api/deploy/zip", {
  auth: true, csrf: true, rateLimit: true,
  handler: async (req, res, body, ip) => {
    const { fields, file } = await parseMultipartBody(req, 50 * 1024 * 1024);
    if (!file) return sendError(res, 400, "No file uploaded");
    if (file.data.length > 50 * 1024 * 1024) return sendError(res, 400, "File exceeds 50MB limit");
    const uploadDir = "/tmp/bundledws-uploads";
    fs.mkdirSync(uploadDir, { recursive: true });
    const zipPath = pathMod.posix.join(uploadDir, `upload_${Date.now()}.zip`);
    fs.writeFileSync(zipPath, file.data);
    try {
      const { inspectZip } = await import("./zip-inspect.js");
      await inspectZip(zipPath);
    } catch (err: any) {
      try { fs.unlinkSync(zipPath); } catch {}
      logActivity(`ZIP upload rejected: ${err.message}`);
      return sendError(res, 400, err.message || "ZIP file rejected");
    }
    const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
    const workspaceDir = `/home/${userName}/Myapp`;
    const logLines: string[] = [];
    const onLog = (line: string) => { logLines.push(line); logActivity(line); };
    logActivity(`Deployment started from zip upload`);
    onLog(`Starting deployment from zip upload`);
    onLog(`Workspace: ${workspaceDir}`);
    const result = await runPipeline({ workspaceDir, zipPath, envVars: fields?.envVars ? (typeof fields.envVars === "object" ? fields.envVars : {}) : undefined, logs: logLines, onLog });
    logActivity(`Deployment ${result.success ? "succeeded" : "failed"}: zip upload (stage: ${result.stage})`);
    try { fs.unlinkSync(zipPath); } catch {}
    return sendJson(res, result.success ? 200 : 400, { ...result, workspaceDir, logs: logLines });
  },
});

// --- APP CONTROL ---
route("POST", "/api/app/start", {
  auth: true, csrf: true,
  handler: async (req, res) => {
    const output = await startApp();
    logActivity("App started via API");
    return sendJson(res, 200, { ok: true, output });
  },
});
route("POST", "/api/app/stop", {
  auth: true, csrf: true,
  handler: async (req, res) => {
    const output = await stopApp();
    logActivity("App stopped via API");
    return sendJson(res, 200, { ok: true, output });
  },
});
route("POST", "/api/app/restart", {
  auth: true, csrf: true,
  handler: async (req, res) => {
    const restartLogs: string[] = [];
    logActivity("Restart initiated");
    const output = await restartWithRebuild((msg: string) => { restartLogs.push(msg); logActivity(msg); });
    logActivity("Restart completed");
    return sendJson(res, 200, { ok: true, output, logs: restartLogs });
  },
});

route("GET", "/api/app/status", {
  auth: true,
  handler: async (req, res) => {
    const status = await getAppStatus();
    const logs = await getAppLogs(20);
    return sendJson(res, 200, { ...status, logs });
  },
});

route("GET", "/api/app/logs", {
  auth: true,
  handler: async (req, res) => {
    const pm2Logs = await getAppLogs(100);
    return sendJson(res, 200, { logs: pm2Logs, activity: getActivityLogs() });
  },
});

// --- ENV ---
route("GET", "/api/app/env", {
  auth: true,
  handler: async (req, res) => {
    const envPath = `${getAppDir()}/.env`;
    const keys: string[] = [];
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, "utf8");
      for (const line of content.split("\n")) {
        const eq = line.indexOf("=");
        if (eq > 0) keys.push(line.substring(0, eq));
      }
    }
    return sendJson(res, 200, { keys });
  },
});

route("POST", "/api/app/env/delete", {
  auth: true, csrf: true,
  handler: async (req, res, body) => {
    const { key } = body;
    if (!key) return sendError(res, 400, "key required");
    const myappDir = getAppDir();
    fs.mkdirSync(myappDir, { recursive: true });
    const envPath = `${myappDir}/.env`;
    let existing: Record<string, string> = {};
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, "utf8");
      for (const line of content.split("\n")) {
        const eq = line.indexOf("=");
        if (eq > 0) existing[line.substring(0, eq)] = line.substring(eq + 1);
      }
    }
    delete existing[key];
    const lines = Object.entries(existing).map(([k, v]) => `${k}=${v}`);
    fs.writeFileSync(envPath, lines.join("\n") + "\n", "utf8");
    const envSystemLines = Object.entries(existing).map(([k, v]) => `${k}="${v}"`);
    fs.writeFileSync("/etc/environment", envSystemLines.join("\n") + "\n", "utf8");
    const profileDir = "/etc/profile.d";
    fs.mkdirSync(profileDir, { recursive: true });
    const profileLines = Object.entries(existing).map(([k, v]) => `export ${k}="${v}"`);
    fs.writeFileSync(pathMod.join(profileDir, "bundledws.sh"), profileLines.join("\n") + "\n", "utf8");
    logActivity(`Environment variable "${key}" deleted`);
    return sendJson(res, 200, { ok: true, keys: Object.keys(existing).sort() });
  },
});

route("PUT", "/api/app/env", {
  auth: true, csrf: true,
  handler: async (req, res, body) => {
    const { env } = body;
    if (!env || typeof env !== "object") return sendError(res, 400, "env must be an object");
    const myappDir = getAppDir();
    fs.mkdirSync(myappDir, { recursive: true });
    const envPath = `${myappDir}/.env`;
    let existing: Record<string, string> = {};
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, "utf8");
      for (const line of content.split("\n")) { const eq = line.indexOf("="); if (eq > 0) existing[line.substring(0, eq)] = line.substring(eq + 1); }
    }
    const addedKeys: string[] = [];
    for (const [key, value] of Object.entries(env)) { validateEnvKey(key); existing[key] = String(value); addedKeys.push(key); }
    const lines = Object.entries(existing).map(([k, v]) => `${k}=${v}`);
    fs.writeFileSync(envPath, lines.join("\n") + "\n", "utf8");
    const envSystemLines = Object.entries(existing).map(([k, v]) => `${k}="${v}"`);
    fs.writeFileSync("/etc/environment", envSystemLines.join("\n") + "\n", "utf8");
    const profileDir = "/etc/profile.d";
    fs.mkdirSync(profileDir, { recursive: true });
    const profileLines = Object.entries(existing).map(([k, v]) => `export ${k}="${v}"`);
    fs.writeFileSync(pathMod.join(profileDir, "bundledws.sh"), profileLines.join("\n") + "\n", "utf8");
    try { fs.chmodSync("/etc/profile.d/bundledws.sh", 0o644); } catch {}
    try { execSync("bash -c 'source /etc/profile.d/bundledws.sh 2>/dev/null || true'", { timeout: 5000 }); } catch {}
    logActivity(`Environment variables updated: ${addedKeys.join(", ")}`);
    logActivity("Redeploying from environment variable update...");
    const restartLogs: string[] = [];
    try { await restartWithRebuild((msg: string) => { restartLogs.push(msg); logActivity(msg); }); } catch { restartLogs.push("Restart with rebuild failed."); logActivity("Restart with rebuild failed."); }
    logActivity("Environment variable update completed.");
    return sendJson(res, 200, { ok: true, keys: Object.keys(existing).sort(), logs: restartLogs });
  },
});

// --- DOMAIN INFO ---
route("GET", "/api/app/domain-info", {
  auth: true,
  handler: async (req, res) => {
    let publicIp = "Unable to detect";
    for (const url of ["https://api.ipify.org", "https://ifconfig.co/ip"]) {
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
        if (resp.ok) { publicIp = (await resp.text()).trim(); break; }
      } catch { /* try next service */ }
    }
    return sendJson(res, 200, { publicIp, port: 3000 });
  },
});

// --- DOMAIN MANAGEMENT ---
const dm = new DomainManager((domainId, msg) => {
  logActivity(`[Domain ${domainId}] ${msg}`);
});

// Helper: parse domain ID from path like /api/domains/:id/action
function matchDomainPath(path: string): { domainId?: string; action?: string } | null {
  const m = path.match(/^\/api\/domains(?:\/([a-f0-9]+)(?:\/([a-z-]+))?)?$/);
  if (!m) return null;
  return { domainId: m[1], action: m[2] };
}

route("GET", "/api/domains", {
  auth: true,
  handler: async (req, res) => {
    const p = await requireAuth(req);
    const domains = listDomains(p.user.role === "admin" ? undefined : p.user.id);
    return sendJson(res, 200, { domains });
  },
});

route("POST", "/api/domains", {
  auth: true, csrf: true, rateLimit: true,
  handler: async (req, res, body, ip) => {
    const p = await requireAuth(req);
    const { domain, mode, dnsProvider, dnsZoneId } = body;

    if (!domain) return sendError(res, 400, "domain required");
    if (!mode) return sendError(res, 400, "mode required (customer_dns or managed_dns)");
    if (mode !== "customer_dns" && mode !== "managed_dns") {
      return sendError(res, 400, "mode must be 'customer_dns' or 'managed_dns'");
    }
    if (mode === "managed_dns" && !dnsProvider) {
      return sendError(res, 400, "dnsProvider required for managed_dns mode");
    }
    if (dnsProvider && dnsProvider !== "cloudflare") {
      return sendError(res, 400, "dnsProvider must be 'cloudflare'");
    }

    // Detect public IP
    let publicIp = "Unable to detect";
    for (const url of ["https://api.ipify.org", "https://ifconfig.co/ip"]) {
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
        if (resp.ok) { publicIp = (await resp.text()).trim(); break; }
      } catch {}
    }

    try {
      const result = await dm.addDomain({
        customerId: p.user.id,
        domain,
        mode,
        publicIp,
        dnsProvider: dnsProvider || undefined,
        dnsZoneId: dnsZoneId || undefined,
      });

      const instructions = generateDnsInstructions(domain, publicIp);

      return sendJson(res, 200, {
        ok: true,
        domain: result,
        dnsInstructions: instructions,
      });
    } catch (err: any) {
      return sendError(res, 400, err.message);
    }
  },
});

route("GET", "/api/domains/stats", {
  auth: true,
  handler: async (req, res) => {
    const p = await requireAuth(req);
    requireAdmin(p);
    return sendJson(res, 200, getDomainStats());
  },
});

// Detect orphaned nginx configs (domains in nginx but not in store)
route("GET", "/api/domains/detect-orphans", {
  auth: true,
  handler: async (req, res) => {
    const p = await requireAuth(req);
    const nginxDomains = listConfiguredDomains();
    const storeDomains = listDomains();
    const storeDomainSet = new Set(storeDomains.map(d => d.domain));
    // Also add www variants
    for (const d of storeDomains) {
      storeDomainSet.add(`www.${d.domain}`);
    }
    const orphans = nginxDomains.filter(name => !storeDomainSet.has(name));
    return sendJson(res, 200, { orphans });
  },
});

// Claim an orphaned nginx domain config into the store
route("POST", "/api/domains/claim-orphan", {
  auth: true, csrf: true, rateLimit: true,
  handler: async (req, res, body, ip) => {
    const p = await requireAuth(req);
    const { domain } = body;
    if (!domain) return sendError(res, 400, "domain required");

    let publicIp = "Unable to detect";
    for (const url of ["https://api.ipify.org", "https://ifconfig.co/ip"]) {
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(3000) });
        if (resp.ok) { publicIp = (await resp.text()).trim(); break; }
      } catch {}
    }

    try {
      const result = await dm.addDomain({
        customerId: p.user.id,
        domain,
        mode: "customer_dns",
        publicIp,
      });
      return sendJson(res, 200, { ok: true, domain: result });
    } catch (err: any) {
      return sendError(res, 400, err.message);
    }
  },
});

// Parameterized domain routes handled in the main request handler below
// because they need path matching with IDs

// ============================================================
// HTTP Server
// ============================================================
http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || "unknown";
  const url = new URL(req.url || "/", "http://localhost");
  const path = url.pathname;
  const method = req.method || "GET";

  try {
    // Static files
    if (method === "GET" && serveStatic(req, res, path)) return;

    // SPA catch-all for frontend routes
    if (method === "GET" && (path === "/" || path.startsWith("/panel") || path.startsWith("/login") || path.startsWith("/dashboard") || path.startsWith("/admin") || path.startsWith("/setup") || path.startsWith("/deploy") || path.startsWith("/logs") || path.startsWith("/env") || path.startsWith("/domain"))) {
      return serveHtml(req, res);
    }

    // API routes — O(1) Map dispatch
    const routeDef = routes.get(`${method}:${path}`);
    if (routeDef) {
      const { handler, auth, csrf, rateLimit } = routeDef;

      if (rateLimit && !checkRateLimit(ip)) return sendError(res, 429, "Too many requests");

      let principal: SessionPrincipal | undefined;
      if (auth) principal = await requireAuth(req);
      if (csrf && principal) requireCsrf(req, principal);

      const ct = req.headers["content-type"] || "";
      const isMultipart = ct.startsWith("multipart/form-data");
      const body = method !== "GET" && !isMultipart ? await parseBody(req) : {};

      await handler(req, res, body, ip);
      return;
    }

    // Parameterized domain routes
    const domainMatch = matchDomainPath(path);
    if (domainMatch && domainMatch.domainId) {
      const { domainId, action } = domainMatch;

      // All domain routes require auth
      let principal: SessionPrincipal;
      try {
        principal = await requireAuth(req);
      } catch {
        return sendError(res, 401, "Unauthorized");
      }

      // Require CSRF for mutations
      const needsCsrf = method !== "GET";
      if (needsCsrf) requireCsrf(req, principal);

      const body = method !== "GET" ? await parseBody(req) : {};

      // GET /api/domains/:id — get domain details
      if (method === "GET" && !action) {
        const domain = getDomain(domainId);
        if (!domain) return sendError(res, 404, "Domain not found");
        // Check ownership
        if (principal.user.role !== "admin" && domain.customerId !== principal.user.id) {
          return sendError(res, 403, "Forbidden");
        }
        const auditLogs = getAuditLogs(domainId, 20);
        const dnsVerifications = getDnsVerifications(domainId, 5);
        const acmeOrder = getAcmeOrder(domainId);
        return sendJson(res, 200, { domain, auditLogs, dnsVerifications, acmeOrder });
      }

      // DELETE /api/domains/:id — remove domain
      if (method === "DELETE" && !action) {
        const domain = getDomain(domainId);
        if (!domain) return sendError(res, 404, "Domain not found");
        if (principal.user.role !== "admin" && domain.customerId !== principal.user.id) {
          return sendError(res, 403, "Forbidden");
        }
        const result = await dm.removeDomain(domainId, principal.user.email);
        return sendJson(res, 200, { ok: result });
      }

      // POST /api/domains/:id/verify-dns
      if (method === "POST" && action === "verify-dns") {
        const result = await dm.verifyDns(domainId);
        return sendJson(res, 200, result);
      }

      // POST /api/domains/:id/request-cert
      if (method === "POST" && action === "request-cert") {
        const domain = getDomain(domainId);
        if (!domain) return sendError(res, 404, "Domain not found");
        // If in dns_verified state, configure nginx first
        if (domain.state === "dns_verified") {
          const nginxOk = await dm.configureNginx(domainId);
          if (!nginxOk) return sendError(res, 400, "Nginx configuration failed");
        }
        const result = await dm.issueCertificate(domainId);
        return sendJson(res, 200, { ok: result });
      }

      // POST /api/domains/:id/renew
      if (method === "POST" && action === "renew") {
        const result = await dm.performRenewal(domainId);
        return sendJson(res, 200, { ok: result });
      }

      // POST /api/domains/:id/retry
      if (method === "POST" && action === "retry") {
        try {
          const result = await dm.retryDomain(domainId);
          return sendJson(res, 200, { ok: result });
        } catch (err: any) {
          return sendError(res, 400, err.message);
        }
      }

      // POST /api/domains/:id/rollback
      if (method === "POST" && action === "rollback") {
        const result = await dm.rollbackDomain(domainId);
        return sendJson(res, 200, { ok: result });
      }

      // POST /api/domains/:id/onboard — full workflow
      if (method === "POST" && action === "onboard") {
        // Start onboarding in background, return immediately
        dm.onboardDomain(domainId).then((ok) => {
          logActivity(`[Domain ${domainId}] Onboarding ${ok ? "completed" : "failed"}`);
        });
        return sendJson(res, 200, { ok: true, message: "Onboarding started" });
      }

      // GET /api/domains/:id/health
      if (method === "GET" && action === "health") {
        const health = await dm.verifyHealth(domainId);
        return sendJson(res, 200, health);
      }

      // GET /api/domains/:id/logs
      if (method === "GET" && action === "logs") {
        const logs = getAuditLogs(domainId, 50);
        return sendJson(res, 200, { logs });
      }

      // GET /api/domains/:id/status
      if (method === "GET" && action === "status") {
        const domain = getDomain(domainId);
        if (!domain) return sendError(res, 404, "Domain not found");
        const acmeOrder = getAcmeOrder(domainId);
        const dnsVerifications = getDnsVerifications(domainId, 3);
        return sendJson(res, 200, { domain, acmeOrder, dnsVerifications });
      }

      return sendError(res, 404, "Unknown domain action");
    }

    return serveHtml(req, res);

  } catch (err: any) {
    const msg = err.message || "Internal error";
    const status = msg === "Unauthorized" ? 401 : msg === "Forbidden" ? 403 : 400;
    sendError(res, status, msg);
  }
}).listen(PORT, "0.0.0.0", () => {
  console.log(`BundledWS running on http://0.0.0.0:${PORT}`);
});

// Start periodic certificate renewal check (every 6 hours)
const RENEWAL_CHECK_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours
setInterval(async () => {
  try {
    const renewed = await dm.checkRenewals();
    if (renewed.length > 0) {
      logActivity(`Auto-renewed certificates: ${renewed.join(", ")}`);
    }
  } catch (err: any) {
    logActivity(`Certificate renewal check failed: ${err.message}`);
  }
}, RENEWAL_CHECK_INTERVAL).unref();

// Also check within first 5 minutes of startup
setTimeout(async () => {
  try {
    const renewed = await dm.checkRenewals();
    if (renewed.length > 0) {
      logActivity(`Startup certificate renewal: ${renewed.join(", ")}`);
    }
  } catch {}
}, 5 * 60 * 1000).unref();
