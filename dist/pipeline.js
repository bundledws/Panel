import fs from "node:fs";
import path from "node:path";
import { runCmd } from "./cmd.js";
import { findNginxBinary, setupNginx } from "./nginx.js";
import { runSecurityCheck } from "./security.js";
const DEPLOY_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes per stage
const LOW_MEM_ENV = { ...process.env, NODE_OPTIONS: "--max-old-space-size=512", npm_config_maxsockets: "2" };
// ============================================================
// STAGE 1: Workspace — Prepare and clear the deploy directory
// ============================================================
async function stageWorkspace(ctx) {
    ctx.onLog("Preparing workspace...");
    const dir = ctx.workspaceDir;
    // Clear existing
    if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        ctx.onLog("Cleared existing workspace");
    }
    fs.mkdirSync(dir, { recursive: true });
    // Verify empty
    const contents = fs.readdirSync(dir);
    if (contents.length > 0)
        throw new Error("Workspace not empty after cleanup");
    ctx.onLog(`Workspace ready: ${dir}`);
}
// ============================================================
// STAGE 2: Source — Clone git repo or extract zip
// ============================================================
async function stageSource(ctx) {
    const dir = ctx.workspaceDir;
    if (ctx.repoUrl) {
        if (!ctx.branch)
            ctx.branch = "main";
        ctx.onLog(`Cloning ${ctx.repoUrl} (branch: ${ctx.branch})...`);
        await runCmd("git", ["clone", "--depth", "1", "--branch", ctx.branch, ctx.repoUrl, dir], undefined, DEPLOY_TIMEOUT_MS, ctx.onLog);
        // Verify
        if (!fs.existsSync(path.join(dir, ".git")))
            throw new Error("Git clone failed: no .git directory");
        const files = fs.readdirSync(dir).filter(f => f !== ".git");
        if (files.length === 0)
            throw new Error("Git clone produced empty repository");
        ctx.onLog("✓ Repository cloned successfully");
    }
    else if (ctx.zipPath) {
        if (!fs.existsSync(ctx.zipPath))
            throw new Error(`Zip file not found: ${ctx.zipPath}`);
        ctx.onLog(`Extracting ${ctx.zipPath}...`);
        // Remove workspace contents first (should be empty from stage 1, but just in case)
        const existing = fs.readdirSync(dir);
        for (const f of existing) {
            fs.rmSync(path.join(dir, f), { recursive: true, force: true });
        }
        await runCmd("unzip", ["-o", ctx.zipPath, "-d", dir], undefined, DEPLOY_TIMEOUT_MS, ctx.onLog);
        // Verify
        const extracted = fs.readdirSync(dir).filter(f => f !== ".git");
        if (extracted.length === 0)
            throw new Error("Zip extraction produced no files");
        ctx.onLog("✓ Zip extracted successfully");
    }
    else {
        throw new Error("No source provided: repoUrl or zipPath required");
    }
}
// ============================================================
// STAGE 3: Detect — Verify it's a valid Next.js project
// ============================================================
async function stageDetect(ctx) {
    const dir = ctx.workspaceDir;
    const pkgPath = path.join(dir, "package.json");
    if (!fs.existsSync(pkgPath))
        throw new Error("Not a Node.js project: no package.json found");
    let pkg;
    try {
        pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    }
    catch {
        throw new Error("Invalid package.json");
    }
    // Check for next dependency
    const hasNext = (pkg.dependencies && pkg.dependencies.next) || (pkg.devDependencies && pkg.devDependencies.next);
    if (!hasNext)
        throw new Error("Not a Next.js project: 'next' not found in dependencies");
    // Check for pages/ or app/ directory
    const hasPages = fs.existsSync(path.join(dir, "pages"));
    const hasApp = fs.existsSync(path.join(dir, "app"));
    const hasSrcPages = fs.existsSync(path.join(dir, "src", "pages"));
    const hasSrcApp = fs.existsSync(path.join(dir, "src", "app"));
    if (!hasPages && !hasApp && !hasSrcPages && !hasSrcApp) {
        throw new Error("Not a Next.js project: no pages/ or app/ directory found");
    }
    // Check for build and start scripts
    if (!pkg.scripts || !pkg.scripts.build)
        throw new Error("Missing build script in package.json");
    if (!pkg.scripts || !pkg.scripts.start)
        throw new Error("Missing start script in package.json");
    ctx.onLog("✓ Next.js project detected");
    ctx.onLog(`  Build script: ${pkg.scripts.build}`);
    ctx.onLog(`  Start script: ${pkg.scripts.start}`);
}
// ============================================================
// STAGE 3.5: Security — Scan project for malicious patterns
// ============================================================
async function stageSecurity(ctx) {
    ctx.onLog("Running security scan...");
    const result = await runSecurityCheck(ctx.workspaceDir);
    if (result.warnings.length > 0) {
        for (const w of result.warnings) {
            ctx.onLog(`  ⚠ ${w}`);
        }
    }
    if (result.maliciousFiles.length > 0) {
        ctx.onLog("  Malicious files detected:");
        for (const f of result.maliciousFiles) {
            ctx.onLog(`    - ${f}`);
        }
    }
    if (!result.passed) {
        for (const issue of result.issues) {
            ctx.onLog(`  ✖ SECURITY ISSUE: ${issue}`);
        }
        throw new Error(`Security check failed: ${result.issues.length} issue(s), ` +
            `${result.maliciousFiles.length} malicious file(s) detected.`);
    }
    ctx.onLog("✓ Security scan passed");
}
// ============================================================
// STAGE 4: Package Manager — Detect and verify
// ============================================================
function detectPackageManager(dir) {
    if (fs.existsSync(path.join(dir, "pnpm-lock.yaml")))
        return "pnpm";
    if (fs.existsSync(path.join(dir, "yarn.lock")))
        return "yarn";
    return "npm";
}
// ============================================================
// STAGE 5: Install — Install dependencies
// ============================================================
async function stageInstall(ctx) {
    const dir = ctx.workspaceDir;
    const pm = detectPackageManager(dir);
    ctx.onLog(`Running ${pm} install...`);
    if (pm === "pnpm") {
        // Ensure pnpm is available
        try {
            await runCmd("which", ["pnpm"], undefined, 5000);
        }
        catch {
            ctx.onLog("pnpm not found, installing...");
            await runCmd("npm", ["install", "-g", "pnpm"], undefined, 60000, ctx.onLog);
        }
        // Detect pnpm version for logging
        try {
            const verResult = await runCmd("pnpm", ["--version"], undefined, 5000);
            ctx.onLog(`Detected pnpm version: ${verResult.stdout.trim()}`);
        }
        catch { }
        // Phase 1: Try pnpm install normally
        ctx.onLog("Checking build approvals...");
        let installError = null;
        try {
            await runCmd("pnpm", ["install"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
        }
        catch (err) {
            installError = err.message || "";
        }
        // Phase 2: If install failed due to ignored build scripts, recover automatically
        if (installError && installError.includes("ERR_PNPM_IGNORED_BUILDS")) {
            // Parse the error to extract package names that need build approval
            // Error format: "Ignored build scripts: sharp@0.34.5" or "Ignored build scripts: sharp@0.34.5, esbuild@0.19.0"
            const match = installError.match(/Ignored build scripts:\s*(.+?)(?:\n|$)/);
            const packages = [];
            if (match) {
                const raw = match[1].trim();
                for (const entry of raw.split(",")) {
                    const pkgName = entry.trim().split("@")[0].trim();
                    if (pkgName && !packages.includes(pkgName)) {
                        packages.push(pkgName);
                    }
                }
            }
            if (packages.length > 0) {
                ctx.onLog("Blocked packages detected:");
                for (const pkg of packages) {
                    ctx.onLog(`  - ${pkg}`);
                }
                // Use the official pnpm approve-builds CLI API (non-interactive).
                // This is the correct way to approve build scripts in pnpm 10+.
                // It modifies the project configuration and updates the lockfile.
                ctx.onLog(`Attempting official approval via: pnpm approve-builds ${packages.join(" ")}`);
                try {
                    await runCmd("pnpm", ["approve-builds", ...packages], dir, 30000, ctx.onLog);
                    ctx.onLog("Approval completed.");
                    ctx.onLog("Verification successful.");
                }
                catch (approveErr) {
                    // If approve-builds fails, try the workspace file approach as fallback
                    ctx.onLog(`⚠ Official approval command failed: ${approveErr.message}`);
                    ctx.onLog("Attempting fallback via pnpm-workspace.yaml...");
                    const wsPath = path.join(dir, "pnpm-workspace.yaml");
                    const hadExistingWs = fs.existsSync(wsPath);
                    let wsContent = "onlyBuiltDependencies:\n";
                    for (const pkg of packages) {
                        wsContent += `  - '${pkg}'\n`;
                    }
                    try {
                        fs.writeFileSync(wsPath, wsContent, "utf8");
                    }
                    finally {
                        if (!hadExistingWs) {
                            try {
                                fs.unlinkSync(wsPath);
                            }
                            catch { }
                        }
                    }
                }
                // Re-run install
                ctx.onLog("Re-running installation...");
                try {
                    await runCmd("pnpm", ["install"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
                }
                catch (retryErr) {
                    // If still failing, try deleting lockfile and retrying once more
                    const retryMsg = retryErr.message || "";
                    if (retryMsg.includes("ERR_PNPM_IGNORED_BUILDS")) {
                        ctx.onLog("⚠ Lockfile may have cached ignored state. Recreating lockfile...");
                        const lockPath = path.join(dir, "pnpm-lock.yaml");
                        if (fs.existsSync(lockPath)) {
                            try {
                                fs.unlinkSync(lockPath);
                            }
                            catch { }
                        }
                        await runCmd("pnpm", ["install"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
                    }
                    else {
                        throw retryErr;
                    }
                }
            }
            else {
                // Could not parse package names — abort with clear error
                throw new Error("pnpm install failed with ERR_PNPM_IGNORED_BUILDS but could not parse blocked package names. " +
                    "Raw error: " + installError);
            }
        }
        else if (installError) {
            // Real error, not ignored builds — re-throw
            throw new Error(installError);
        }
        ctx.onLog("Dependencies installed.");
        ctx.onLog("Native packages built successfully.");
    }
    else if (pm === "yarn") {
        await runCmd("yarn", ["install"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
        ctx.onLog("✓ Dependencies installed");
    }
    else {
        await runCmd("npm", ["install"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
        ctx.onLog("✓ Dependencies installed");
    }
    // Verify next binary exists
    const nextBin = path.join(dir, "node_modules", ".bin", "next");
    if (!fs.existsSync(nextBin))
        throw new Error("Install failed: next binary not found in node_modules/.bin/next");
    ctx.onLog("✓ Dependencies installed successfully");
}
// ============================================================
// STAGE 6: Build — Run the project's build command
// ============================================================
async function stageBuild(ctx) {
    const dir = ctx.workspaceDir;
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    const buildCmd = pkg.scripts.build;
    const pm = detectPackageManager(dir);
    ctx.onLog(`Building with: ${pm} run build`);
    if (pm === "pnpm") {
        await runCmd("pnpm", ["run", "build"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
    }
    else if (pm === "yarn") {
        await runCmd("yarn", ["build"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
    }
    else {
        await runCmd("npm", ["run", "build"], dir, DEPLOY_TIMEOUT_MS, ctx.onLog, LOW_MEM_ENV);
    }
    // Verify .next directory exists
    const nextDir = path.join(dir, ".next");
    if (!fs.existsSync(nextDir))
        throw new Error("Build failed: .next directory not found");
    const buildId = path.join(nextDir, "BUILD_ID");
    if (fs.existsSync(buildId)) {
        const id = fs.readFileSync(buildId, "utf8").trim();
        ctx.onLog(`✓ Build complete (BUILD_ID: ${id})`);
    }
    else {
        ctx.onLog("✓ Build complete");
    }
}
// ============================================================
// STAGE 7: Environment — Write .env.local with user vars
// ============================================================
async function stageEnv(ctx) {
    const dir = ctx.workspaceDir;
    if (!ctx.envVars || Object.keys(ctx.envVars).length === 0) {
        ctx.onLog("No environment variables to set");
        return;
    }
    const lines = [];
    for (const [key, value] of Object.entries(ctx.envVars)) {
        lines.push(`${key}=${value}`);
    }
    fs.writeFileSync(path.join(dir, ".env.local"), lines.join("\n") + "\n", "utf8");
    ctx.onLog(`✓ ${Object.keys(ctx.envVars).length} environment variable(s) written to .env.local`);
}
// ============================================================
// STAGE 8: PM2 — Start the app with PM2
// ============================================================
async function stagePM2(ctx) {
    const dir = ctx.workspaceDir;
    const nextBin = path.join(dir, "node_modules", ".bin", "next");
    const appName = "nextapp";
    // Stop existing if any
    try {
        await runCmd("pm2", ["stop", appName], undefined, 10000);
    }
    catch { }
    try {
        await runCmd("pm2", ["delete", appName], undefined, 10000);
    }
    catch { }
    // Kill any stale process holding port 3000 to prevent EADDRINUSE crashes
    try {
        await runCmd("sh", ["-c", "lsof -ti:3000 | xargs kill -9 2>/dev/null || true"], undefined, 5000);
    }
    catch { }
    // Create ecosystem file
    // Use the actual JS entry point, not the shell wrapper at .bin/next
    // node_modules/.bin/next is a shell script (#!/bin/sh shim), not a JS file.
    // Node.js cannot execute shell scripts — it throws SyntaxError.
    // The real JS entry is at node_modules/next/dist/bin/next.
    const nextJsEntry = path.join(dir, "node_modules", "next", "dist", "bin", "next");
    const entryPoint = fs.existsSync(nextJsEntry) ? nextJsEntry : nextBin;
    const ecoConfig = {
        apps: [{
                name: appName,
                cwd: dir,
                script: entryPoint,
                args: ["start", "-p", "3000"],
                exec_mode: "fork",
                instances: 1,
                autorestart: true,
                max_restarts: 10,
                restart_delay: 1000,
                env: { NODE_ENV: "production", PORT: "3000" },
                error_file: path.join(dir, ".pm2", "err.log"),
                out_file: path.join(dir, ".pm2", "out.log"),
                merge_logs: true,
                log_date_format: "YYYY-MM-DD HH:mm:ss Z"
            }]
    };
    const ecoDir = path.join(dir, ".pm2");
    fs.mkdirSync(ecoDir, { recursive: true });
    fs.writeFileSync(path.join(ecoDir, "ecosystem.config.js"), `module.exports = ${JSON.stringify(ecoConfig, null, 2)};\n`, "utf8");
    ctx.onLog("Starting application...");
    await runCmd("pm2", ["start", path.join(ecoDir, "ecosystem.config.js")], undefined, 30000, ctx.onLog);
    // Poll PM2 until the process reaches a stable state.
    // PM2 starts processes asynchronously — the process goes through
    // transient states ("launching", "waiting restart") before reaching
    // "online". A single-shot poll would catch the transient state.
    // We poll every 1s and require 3 consecutive "online" readings.
    ctx.onLog("Waiting for stable startup...");
    const MAX_POLLS = 30;
    let onlineCount = 0;
    let lastRestartCount = -1;
    let lastStatus = "unknown";
    let appPid;
    let crashLoopStreak = 0;
    let collectedLogs = "";
    // Helper to read PM2 error logs
    function readPm2ErrorLog() {
        try {
            const errPath = path.join(ecoDir, "err.log");
            if (fs.existsSync(errPath)) {
                return fs.readFileSync(errPath, "utf8").trim();
            }
        }
        catch { }
        return "";
    }
    for (let i = 1; i <= MAX_POLLS; i++) {
        await new Promise(r => setTimeout(r, 1000));
        let result;
        try {
            result = await runCmd("pm2", ["jlist"], undefined, 5000);
        }
        catch {
            ctx.onLog(`Poll #${i}: PM2 not responding yet`);
            continue;
        }
        let list;
        try {
            list = JSON.parse(result.stdout);
        }
        catch {
            ctx.onLog(`Poll #${i}: Could not parse PM2 output`);
            continue;
        }
        const app = list.find((p) => p.name === appName);
        if (!app) {
            ctx.onLog(`Poll #${i}: Process not found`);
            onlineCount = 0;
            continue;
        }
        const status = app.pm2_env?.status || "unknown";
        const restartCount = app.pm2_env?.restart_time ?? 0;
        appPid = app.pid;
        ctx.onLog(`Poll #${i}: Status: ${status}`);
        // Detect crash loops: if restart count increases between polls
        if (lastRestartCount >= 0 && restartCount > lastRestartCount) {
            crashLoopStreak++;
            ctx.onLog(`  Restart count: ${restartCount} (streak: ${crashLoopStreak})`);
            // Collect PM2 error logs on each restart to capture the crash reason
            if (!collectedLogs) {
                // Read the PM2 error log file directly
                collectedLogs = readPm2ErrorLog();
                if (!collectedLogs) {
                    try {
                        const pm2logs = await runCmd("pm2", ["logs", appName, "--lines", "20", "--nostream"], undefined, 5000);
                        collectedLogs = pm2logs.stdout;
                    }
                    catch { }
                }
            }
            // After 3 restart streaks, abort early — the app is crashing persistently
            if (crashLoopStreak >= 3) {
                const reason = collectedLogs
                    ? `Application error log:\n${collectedLogs}`
                    : "No error log captured. Check pm2 logs manually.";
                throw new Error(`Application is crashing after startup (${restartCount} restarts).\n` +
                    reason);
            }
        }
        lastRestartCount = restartCount;
        lastStatus = status;
        if (status === "errored" || status === "stopped") {
            // Collect diagnostics before failing
            let stderrLog = collectedLogs;
            if (!stderrLog) {
                stderrLog = readPm2ErrorLog();
                if (!stderrLog) {
                    try {
                        const logs = await runCmd("pm2", ["logs", appName, "--lines", "20", "--nostream"], undefined, 5000);
                        stderrLog = logs.stdout;
                    }
                    catch { }
                }
            }
            throw new Error(`Application exited unexpectedly.\n` +
                `PM2 status: ${status}\n` +
                `Restart count: ${restartCount}\n` +
                `Recent logs:\n${stderrLog || "No logs captured"}`);
        }
        if (status === "online") {
            onlineCount++;
            if (onlineCount >= 3) {
                ctx.onLog("Application responding on port 3000");
                ctx.onLog("Startup stable.");
                ctx.onLog(`✓ App running with PM2 (pid: ${appPid})`);
                // Save PM2 process list so nextapp survives reboot
                try {
                    await runCmd("pm2", ["save"], undefined, 10000);
                    ctx.onLog("✓ PM2 process list saved for reboot persistence");
                }
                catch {
                    ctx.onLog("⚠ Could not save PM2 process list");
                }
                return;
            }
        }
        else {
            onlineCount = 0;
        }
    }
    // Timeout reached — collect final diagnostics
    if (!collectedLogs) {
        collectedLogs = readPm2ErrorLog();
        if (!collectedLogs) {
            try {
                const pm2logs = await runCmd("pm2", ["logs", appName, "--lines", "20", "--nostream"], undefined, 5000);
                collectedLogs = pm2logs.stdout;
            }
            catch { }
        }
    }
    const crashMsg = lastRestartCount > 0
        ? `\nApplication is crashing after startup. Restart count: ${lastRestartCount}` +
            (collectedLogs ? `\nError log:\n${collectedLogs}` : "")
        : "";
    throw new Error(`PM2 startup timeout after ${MAX_POLLS} seconds.` +
        crashMsg +
        `\nLast status: ${lastStatus}`);
}
// ============================================================
// STAGE 9: Nginx — Configure reverse proxy (with optional SSL)
// ============================================================
async function stageNginx(ctx) {
    // Check for SSL config from environment (set during install.sh)
    const domain = process.env.BWS_DOMAIN;
    const certPath = process.env.BWS_SSL_CERT;
    const keyPath = process.env.BWS_SSL_KEY;
    const ssl = domain && certPath && keyPath && fs.existsSync(certPath)
        ? { domain, certPath, keyPath }
        : undefined;
    if (ssl) {
        ctx.onLog(`SSL enabled for domain: ${ssl.domain}`);
    }
    await setupNginx((msg) => ctx.onLog(msg), ssl);
}
// ============================================================
// STAGE 10: Health — Verify the app is running
// ============================================================
async function stageHealth(ctx) {
    ctx.onLog("Verifying application health...");
    // Check port 3000 is listening
    let portOpen = false;
    for (let i = 0; i < 15; i++) {
        try {
            await runCmd("node", ["-e", `
        require('http').get('http://127.0.0.1:3000', (r) => {
          process.exit(r.statusCode === 200 ? 0 : 1);
        }).on('error', () => process.exit(1));
      `], undefined, 5000);
            portOpen = true;
            break;
        }
        catch {
            await new Promise(r => setTimeout(r, 1000));
        }
    }
    if (portOpen) {
        ctx.onLog("✓ App is responding on port 3000");
    }
    else {
        throw new Error("Health check failed: app not responding on port 3000 after 15 seconds");
    }
    // Verify PM2 process
    const statusResult = await runCmd("pm2", ["jlist"], undefined, 5000);
    const list = JSON.parse(statusResult.stdout);
    const app = list.find((p) => p.name === "nextapp");
    if (!app)
        throw new Error("Health check failed: PM2 process not found");
    if (app.pm2_env?.status !== "online")
        throw new Error(`Health check failed: PM2 status is ${app.pm2_env?.status}`);
    ctx.onLog("✓ PM2 process confirmed running");
    ctx.onLog("✓ Health check passed");
}
// ============================================================
// Pipeline Orchestrator
// ============================================================
const COMMON_STAGES = [
    { name: "workspace", fn: stageWorkspace },
    { name: "source", fn: stageSource },
    { name: "detect", fn: stageDetect },
    { name: "security", fn: stageSecurity },
    { name: "install", fn: stageInstall },
    { name: "build", fn: stageBuild },
    { name: "environment", fn: stageEnv },
    { name: "pm2", fn: stagePM2 },
];
const FINAL_STAGES = [
    { name: "health", fn: stageHealth },
];
export async function runPipeline(ctx) {
    ctx.logs = [];
    // Build stage list dynamically: only add nginx if binary is installed
    const stages = [...COMMON_STAGES];
    if (findNginxBinary()) {
        stages.push({ name: "nginx", fn: stageNginx });
    }
    stages.push(...FINAL_STAGES);
    for (const stage of stages) {
        ctx.onLog(`\n=== ${stage.name.toUpperCase()} ===`);
        try {
            await stage.fn(ctx);
            ctx.onLog(`=== ${stage.name} complete ===\n`);
        }
        catch (err) {
            const error = err.message || "Unknown error";
            ctx.onLog(`\n!!! ${stage.name} FAILED: ${error}`);
            return { success: false, stage: stage.name, error, logs: ctx.logs };
        }
    }
    ctx.onLog("\n✓ DEPLOYMENT COMPLETE");
    return { success: true, stage: "complete", logs: ctx.logs };
}
//# sourceMappingURL=pipeline.js.map