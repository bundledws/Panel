import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { runCmd } from "./cmd.js";
const NGINX_AVAIL_DIR = "/etc/nginx/sites-available";
const NGINX_ENABLED_DIR = "/etc/nginx/sites-enabled";
const NGINX_CONFIG_PATH = path.join(NGINX_AVAIL_DIR, "nextapp");
const NGINX_SYMLINK_PATH = path.join(NGINX_ENABLED_DIR, "nextapp");
// ============================================================
// Domain Config (kept for backward compatibility with server.ts)
// ============================================================
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
function renderConfig(domain, appPort) {
    if (!DOMAIN_REGEX.test(domain))
        throw new Error("Invalid domain format");
    if (domain === "localhost" || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain))
        throw new Error("IP addresses and localhost not allowed");
    if (!Number.isInteger(appPort) || appPort < 1 || appPort > 65535)
        throw new Error("Invalid port");
    return `server {
    listen 80;
    server_name ${domain};
    server_tokens off;
    location / {
        proxy_pass http://127.0.0.1:${appPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
}
function renderSelfSignedConfig(appPort) {
    return `server {
    listen 80;
    server_name _;
    server_tokens off;
    location / {
        proxy_pass http://127.0.0.1:${appPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
}
// ============================================================
// SSL Config — Full HTTPS setup with catch-all fallback
// Generates a two-server-block config:
//   1. Catch-all on port 80 → proxies ANY domain to appPort
//      (redirects known subdomain to HTTPS, serves others on HTTP)
//   2. Named server on port 443 with SSL → proxies to appPort
// ============================================================
export function renderSSLConfig(domain, certPath, keyPath, appPort, panelPort) {
    const escapedDomain = domain.replace(/\./g, "\\.");
    return `# Catch-all port 80 — 100% guarantee: ANY domain → port ${appPort}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;

    # Managed subdomain → redirect to HTTPS
    if ($host ~* ^vps-[a-f0-9]+\\.${escapedDomain}$) {
        return 301 https://$host$request_uri;
    }

    # Any other domain → serve app directly (no cert needed)
    location / {
        proxy_pass http://127.0.0.1:${appPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Managed subdomain — HTTPS with valid Let's Encrypt cert
server {
    listen 443 ssl;
    http2 on;
    server_name ${domain};
    server_tokens off;

    ssl_certificate ${certPath};
    ssl_certificate_key ${keyPath};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve auto;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # Customer's deployed Next.js app at root
    location / {
        proxy_pass http://127.0.0.1:${appPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Panel API
    location /api/ {
        proxy_pass http://127.0.0.1:${panelPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Panel SPA (control panel interface)
    location /panel/ {
        proxy_pass http://127.0.0.1:${panelPort}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
}
async function writeConfig(config) {
    fs.mkdirSync(NGINX_AVAIL_DIR, { recursive: true });
    fs.writeFileSync(NGINX_CONFIG_PATH, config, "utf8");
    try {
        fs.unlinkSync(NGINX_SYMLINK_PATH);
    }
    catch { }
    try {
        fs.symlinkSync(NGINX_CONFIG_PATH, NGINX_SYMLINK_PATH);
    }
    catch { }
}
// ============================================================
// Binary Detection (sync — called from pipeline.ts sync context)
// ============================================================
export function findNginxBinary() {
    const candidates = ["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/usr/bin/nginx", "/opt/nginx/sbin/nginx"];
    for (const p of candidates) {
        if (fs.existsSync(p))
            return p;
    }
    return null;
}
// ============================================================
// Detection
// ============================================================
async function detectNginxRunning() {
    const processes = [];
    let systemd = false;
    try {
        const result = await runCmd("systemctl", ["is-active", "nginx"], undefined, 5000);
        systemd = result.stdout.trim() === "active";
    }
    catch { }
    try {
        const result = await runCmd("pgrep", ["-a", "nginx"], undefined, 5000);
        const lines = result.stdout.split("\n").filter(l => l.trim());
        for (const line of lines) {
            if (line.trim())
                processes.push(line.trim());
        }
    }
    catch { }
    return { running: systemd || processes.length > 0, processes, systemd };
}
// ============================================================
// Kill Process Tree
// ============================================================
async function killNginxProcessTree() {
    const errors = [];
    let killed = 0;
    try {
        await runCmd("systemctl", ["stop", "nginx"], undefined, 10000);
    }
    catch { }
    try {
        await runCmd("pkill", ["-9", "nginx"], undefined, 10000);
        killed++;
    }
    catch { /* no process to kill */ }
    try {
        await runCmd("pgrep", ["nginx"], undefined, 5000);
        errors.push("Some nginx processes could not be killed");
    }
    catch { /* all killed */ }
    return { killed, errors };
}
// ============================================================
// Clear Configuration
// ============================================================
function clearNginxConfig() {
    let removed = 0;
    if (fs.existsSync(NGINX_ENABLED_DIR)) {
        const files = fs.readdirSync(NGINX_ENABLED_DIR);
        for (const f of files) {
            try {
                fs.unlinkSync(path.join(NGINX_ENABLED_DIR, f));
                removed++;
            }
            catch { }
        }
    }
    if (fs.existsSync(NGINX_AVAIL_DIR)) {
        const files = fs.readdirSync(NGINX_AVAIL_DIR);
        for (const f of files) {
            try {
                fs.unlinkSync(path.join(NGINX_AVAIL_DIR, f));
                removed++;
            }
            catch { }
        }
    }
    return { removed };
}
// ============================================================
// Ensure Installed
// ============================================================
async function ensureNginxInstalled() {
    if (findNginxBinary())
        return true;
    try {
        await runCmd("apt-get", ["install", "-y", "-qq", "nginx"], undefined, 120000);
    }
    catch { }
    return findNginxBinary() !== null;
}
// ============================================================
// Generate Proxy Config
// ============================================================
function generateProxyConfig() {
    return `server {
    listen 80;
    listen [::]:80;
    server_name _;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
}
// ============================================================
// Write Config
// ============================================================
function writeNginxConfig(config) {
    fs.mkdirSync(NGINX_AVAIL_DIR, { recursive: true });
    fs.mkdirSync(NGINX_ENABLED_DIR, { recursive: true });
    fs.writeFileSync(NGINX_CONFIG_PATH, config, "utf8");
    try {
        fs.unlinkSync(NGINX_SYMLINK_PATH);
    }
    catch { }
    fs.symlinkSync(NGINX_CONFIG_PATH, NGINX_SYMLINK_PATH);
}
// ============================================================
// Test Config
// ============================================================
export async function testNginxConfig() {
    return new Promise((resolve) => {
        const stderr = [];
        const child = spawn("nginx", ["-t"], { stdio: ["ignore", "pipe", "pipe"], shell: false });
        child.stderr.on("data", (c) => stderr.push(c));
        child.on("close", (code) => {
            const output = Buffer.concat(stderr).toString("utf8").trim();
            resolve({ valid: code === 0, output });
        });
        child.on("error", (err) => resolve({ valid: false, output: err.message }));
    });
}
// ============================================================
// Reload Nginx
// ============================================================
export async function reloadNginx() {
    const test = await testNginxConfig();
    if (!test.valid)
        return { ok: false, output: `Config test failed: ${test.output}` };
    try {
        await runCmd("systemctl", ["reload", "nginx"], undefined, 15000);
        return { ok: true, output: "Nginx reloaded successfully" };
    }
    catch {
        // fallback: try nginx -s reload, then systemctl restart
        try {
            await runCmd("nginx", ["-s", "reload"], undefined, 10000);
            return { ok: true, output: "Nginx reloaded successfully" };
        }
        catch {
            try {
                await runCmd("systemctl", ["restart", "nginx"], undefined, 15000);
                return { ok: true, output: "Nginx restarted successfully" };
            }
            catch (e) {
                return { ok: false, output: `Failed to reload nginx: ${e.message}` };
            }
        }
    }
}
// ============================================================
// Verify Listening
// ============================================================
async function verifyNginxListening() {
    let ipv4 = false;
    let ipv6 = false;
    try {
        const result = await runCmd("ss", ["-tlnp"], undefined, 5000);
        ipv4 = result.stdout.includes("0.0.0.0:80") || result.stdout.includes("*:80");
        ipv6 = result.stdout.includes("[::]:80");
    }
    catch { }
    return { ipv4, ipv6 };
}
// ============================================================
// Full Setup Orchestration
// ============================================================
// ============================================================
// NGINX Lock — file-based mutex for concurrent operations
// ============================================================
const NGINX_LOCK_PATH = "/tmp/bundledws-nginx.lock";
export async function withNginxLock(fn, timeoutMs = 30000) {
    const start = Date.now();
    let acquired = false;
    while (Date.now() - start < timeoutMs) {
        try {
            // Atomic create using O_EXCL
            fs.writeFileSync(NGINX_LOCK_PATH + "." + process.pid, String(process.pid), { flag: "wx" });
            // Rename to acquire (atomic on same filesystem)
            fs.renameSync(NGINX_LOCK_PATH + "." + process.pid, NGINX_LOCK_PATH);
            acquired = true;
            break;
        }
        catch {
            // Lock held — check if stale (> 5 minutes)
            try {
                const stat = fs.statSync(NGINX_LOCK_PATH);
                if (Date.now() - stat.mtimeMs > 300000) {
                    // Stale lock — break it
                    try {
                        fs.unlinkSync(NGINX_LOCK_PATH);
                    }
                    catch { }
                    continue;
                }
            }
            catch { }
            // Wait and retry
            await new Promise(r => setTimeout(r, 500));
        }
    }
    if (!acquired) {
        throw new Error("Could not acquire nginx lock within " + timeoutMs + "ms");
    }
    try {
        return await fn();
    }
    finally {
        try {
            fs.unlinkSync(NGINX_LOCK_PATH);
        }
        catch { }
    }
}
// ============================================================
// Shared Snippet Files
// ============================================================
const SNIPPETS_DIR = "/etc/nginx/bundledws/snippets";
const PROXY_HEADERS_PATH = SNIPPETS_DIR + "/proxy-headers.conf";
const SSL_DEFAULTS_PATH = SNIPPETS_DIR + "/ssl-defaults.conf";
const PROXY_HEADERS_CONTENT = `proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection 'upgrade';
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_cache_bypass $http_upgrade;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;
proxy_read_timeout 86400s;
proxy_send_timeout 86400s;
`;
const SSL_DEFAULTS_CONTENT = `ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_ecdh_curve auto;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
`;
export function ensureSnippets() {
    fs.mkdirSync(SNIPPETS_DIR, { recursive: true });
    fs.writeFileSync(PROXY_HEADERS_PATH, PROXY_HEADERS_CONTENT, "utf8");
    fs.writeFileSync(SSL_DEFAULTS_PATH, SSL_DEFAULTS_CONTENT, "utf8");
}
// ============================================================
// Per-Domain Nginx Config Generation
// ============================================================
export function generateDefaultServerBlock() {
    return `# Catch-all — reject unknown hosts
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    return 444;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    server_tokens off;
    ssl_reject_handshake on;
    return 444;
}
`;
}
// Cloudflare IP ranges for real_ip configuration
// These are used to restore the original client IP when behind Cloudflare proxy
const CLOUDFLARE_REAL_IP_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/32",
    "2c0f:f350::/32",
];
function generateCloudflareRealIpBlock() {
    let block = "";
    for (const range of CLOUDFLARE_REAL_IP_RANGES) {
        block += `    set_real_ip_from ${range};\n`;
    }
    block += "    real_ip_header CF-Connecting-IP;\n";
    block += "    real_ip_recursive on;\n";
    return block;
}
export function generatePerDomainConfig(domain, appPort, certPath, keyPath, acmeChallengeDir) {
    const wwwDomain = "www." + domain;
    const realIpBlock = generateCloudflareRealIpBlock();
    let config = `# Domain: ${domain}
# Auto-generated by BundledWS — do not edit manually

# HTTP → HTTPS redirect (with ACME challenge location)
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} ${wwwDomain};
    server_tokens off;

    # Restore real client IP when behind Cloudflare proxy
${realIpBlock}

    # ACME HTTP-01 challenge location (before redirect)
    location /.well-known/acme-challenge/ {
        root ${acmeChallengeDir};
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

`;
    if (certPath && keyPath) {
        config += `# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${domain} ${wwwDomain};
    server_tokens off;

    # Restore real client IP when behind Cloudflare proxy
${realIpBlock}

    include ${SSL_DEFAULTS_PATH};

    ssl_certificate     ${certPath};
    ssl_certificate_key ${keyPath};

    location / {
        include ${PROXY_HEADERS_PATH};
        proxy_pass http://127.0.0.1:${appPort};
    }
}
`;
    }
    else {
        // No cert yet — serve HTTP-only (during initial setup before cert issuance)
        config += `# HTTP-only server (pre-certificate)
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} ${wwwDomain};
    server_tokens off;

    # Restore real client IP when behind Cloudflare proxy
${realIpBlock}

    include ${PROXY_HEADERS_PATH};
    proxy_pass http://127.0.0.1:${appPort};
}
`;
    }
    return config;
}
// ============================================================
// Write / Remove Domain Config
// ============================================================
const NGINX_AVAIL_DOMAIN_DIR = "/etc/nginx/bundledws/domains-available";
const NGINX_ENABLED_DOMAIN_DIR = "/etc/nginx/bundledws/domains-enabled";
const ACME_CHALLENGE_DIR = "/var/lib/letsencrypt";
function getDomainConfigPath(domainId) {
    return path.join(NGINX_AVAIL_DOMAIN_DIR, `domain-${domainId}.conf`);
}
function getDomainEnabledPath(domainId) {
    return path.join(NGINX_ENABLED_DOMAIN_DIR, `domain-${domainId}.conf`);
}
/**
 * Write a per-domain nginx config atomically.
 * Returns the config hash for change detection.
 */
export function writeDomainConfig(domainId, config) {
    const configPath = getDomainConfigPath(domainId);
    const enabledPath = getDomainEnabledPath(domainId);
    // Create directories
    fs.mkdirSync(NGINX_AVAIL_DOMAIN_DIR, { recursive: true });
    fs.mkdirSync(NGINX_ENABLED_DOMAIN_DIR, { recursive: true });
    fs.mkdirSync(ACME_CHALLENGE_DIR, { recursive: true });
    // Ensure snippets exist
    ensureSnippets();
    // Write config atomically (write to tmp, then rename)
    const tmpPath = configPath + ".tmp." + Date.now();
    fs.writeFileSync(tmpPath, config, "utf8");
    fs.renameSync(tmpPath, configPath);
    // Create symlink in enabled
    try {
        fs.unlinkSync(enabledPath);
    }
    catch { }
    fs.symlinkSync(configPath, enabledPath);
    // Compute hash for change tracking
    const configHash = crypto.createHash("sha256").update(config).digest("hex");
    return { configPath, configHash };
}
/**
 * Remove a per-domain nginx config and optionally keep a backup.
 */
export function removeDomainConfig(domainId, keepBackup = false) {
    const configPath = getDomainConfigPath(domainId);
    const enabledPath = getDomainEnabledPath(domainId);
    let removed = false;
    // Remove enabled symlink
    try {
        fs.unlinkSync(enabledPath);
        removed = true;
    }
    catch { }
    if (keepBackup) {
        // Keep the config file in available (rename .bak)
        if (fs.existsSync(configPath)) {
            try {
                fs.renameSync(configPath, configPath + ".bak");
            }
            catch { }
        }
    }
    else {
        // Remove both
        try {
            fs.unlinkSync(configPath);
        }
        catch { }
    }
    return removed;
}
/**
 * Restore the default catch-all server block.
 */
export function writeDefaultServerBlock() {
    const configPath = "/etc/nginx/sites-available/default";
    const enabledPath = "/etc/nginx/sites-enabled/default";
    const config = generateDefaultServerBlock();
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, config, "utf8");
    try {
        fs.unlinkSync(enabledPath);
    }
    catch { }
    fs.symlinkSync(configPath, enabledPath);
}
/**
 * List all configured domain server names for duplicate detection.
 */
export function listConfiguredDomains() {
    const domains = [];
    const dirs = [NGINX_ENABLED_DOMAIN_DIR, "/etc/nginx/sites-enabled"];
    for (const dir of dirs) {
        if (!fs.existsSync(dir))
            continue;
        try {
            const files = fs.readdirSync(dir);
            for (const file of files) {
                const filePath = path.join(dir, file);
                if (!fs.statSync(filePath).isFile() && !fs.statSync(filePath).isSymbolicLink())
                    continue;
                try {
                    const content = fs.readFileSync(filePath, "utf8");
                    // Extract server_name directives
                    const matches = content.match(/server_name\s+([^;]+);/g);
                    if (matches) {
                        for (const m of matches) {
                            const names = m.replace(/server_name\s+/, "").replace(";", "").trim().split(/\s+/);
                            for (const name of names) {
                                if (name !== "_" && !domains.includes(name)) {
                                    domains.push(name);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }
    return domains;
}
// ============================================================
// Full Setup Orchestration (existing, extended)
// ============================================================
export async function setupNginx(onLog, ssl) {
    const log = (msg) => { if (onLog)
        onLog(msg); };
    log("Configuring nginx...");
    // Step 1: Detect
    const detection = await detectNginxRunning();
    if (detection.running) {
        log(`Existing nginx detected (systemd: ${detection.systemd}, processes: ${detection.processes.length})`);
    }
    else {
        log("No existing nginx processes detected.");
    }
    // Step 2: Kill existing processes
    if (detection.running) {
        log("Stopping existing nginx processes...");
        const killResult = await killNginxProcessTree();
        log(`Killed ${killResult.killed} process group(s).`);
        if (killResult.errors.length) {
            for (const err of killResult.errors)
                log(`  Warning: ${err}`);
        }
    }
    // Step 3: Clear old configs
    log("Clearing old nginx configurations...");
    const clearResult = clearNginxConfig();
    log(`Removed ${clearResult.removed} old config file(s).`);
    // Step 4: Ensure installed
    log("Ensuring nginx is installed...");
    if (!(await ensureNginxInstalled())) {
        throw new Error("Failed to install nginx. Please install it manually: apt-get install nginx");
    }
    const nginxBin = findNginxBinary();
    log(`Found nginx at: ${nginxBin}`);
    // Step 5: Generate and write config
    log("Generating reverse proxy configuration...");
    const APP_PORT = 3000;
    const PANEL_PORT = 8080;
    let config;
    if (ssl) {
        log(`SSL enabled for domain: ${ssl.domain}`);
        config = renderSSLConfig(ssl.domain, ssl.certPath, ssl.keyPath, APP_PORT, PANEL_PORT);
    }
    else {
        config = generateProxyConfig();
    }
    writeNginxConfig(config);
    log("Reverse proxy configuration written.");
    // Step 6: Test config
    log("Testing nginx configuration...");
    const testResult = await testNginxConfig();
    if (!testResult.valid) {
        throw new Error(`Nginx configuration test failed: ${testResult.output}`);
    }
    log("Nginx configuration test passed.");
    // Step 7: Reload/start
    log("Starting nginx...");
    const reloadResult = await reloadNginx();
    if (!reloadResult.ok) {
        throw new Error(`Failed to start nginx: ${reloadResult.output}`);
    }
    log("Nginx started successfully.");
    // Step 8: Verify listening
    // With SSL, we check both port 80 and 443
    const listening = await verifyNginxListening();
    log(`Port 80 proxy: ${listening.ipv4 ? "OK" : "FAILED"}`);
    log(`IPv6: ${listening.ipv6 ? "OK" : "FAILED"}`);
    if (ssl) {
        try {
            const sslCheck = await runCmd("ss", ["-tlnp"], undefined, 5000);
            const has443 = sslCheck.stdout.includes("0.0.0.0:443") || sslCheck.stdout.includes("*:443");
            log(`Port 443 (HTTPS): ${has443 ? "OK" : "FAILED"}`);
        }
        catch {
            log("Port 443 (HTTPS): Could not verify");
        }
    }
    if (!listening.ipv4) {
        log("Warning: Nginx is not listening on IPv4 port 80. Check firewall rules.");
    }
}
//# sourceMappingURL=nginx.js.map