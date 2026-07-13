import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCmd } from "./cmd.js";

// Detect the app root directory (parent of dist/)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT_DIR = path.resolve(__dirname, "..");
const APP_ROOT = path.join(APP_ROOT_DIR, "pm2");

export type DeployLogCallback = (line: string) => void;

function detectPackageManager(dir: string): string {
  if (fs.existsSync(path.join(dir, "pnpm-lock.yaml"))) return "pnpm";
  if (fs.existsSync(path.join(dir, "yarn.lock"))) return "yarn";
  return "npm";
}

export async function restartWithRebuild(onLog?: (msg: string) => void): Promise<string> {
  const log = (msg: string) => { if (onLog) onLog(msg); };
  const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
  const appDir = `/home/${userName}/Myapp`;
  
  // Stop the app
  log("Stopping app...");
  try {
    await runCmd("pm2", ["stop", "nextapp"], undefined, 10000);
  } catch {}
  
  // Reinstall dependencies if package.json exists
  const pkgPath = path.posix.join(appDir, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pm = detectPackageManager(appDir);
    if (pm === "pnpm") {
      log("Reinstalling dependencies with pnpm...");
      try { await runCmd("which", ["pnpm"], undefined, 5000); } catch {
        await runCmd("npm", ["install", "-g", "pnpm"], undefined, 60000);
      }
      await runCmd("pnpm", ["install"], appDir, 300000);
    } else if (pm === "yarn") {
      log("Reinstalling dependencies with yarn...");
      await runCmd("yarn", ["install"], appDir, 300000);
    } else {
      log("Reinstalling dependencies with npm...");
      await runCmd("npm", ["install"], appDir, 300000);
    }
    log("Dependencies reinstalled.");
    
    // Rebuild the app
    log("Rebuilding app...");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    if (pkg.scripts && pkg.scripts.build) {
      if (pm === "pnpm") await runCmd("pnpm", ["run", "build"], appDir, 300000);
      else if (pm === "yarn") await runCmd("yarn", ["build"], appDir, 300000);
      else await runCmd("npm", ["run", "build"], appDir, 300000);
    }
    log("Build complete.");
  }
  
  // Start the app
  log("Starting app...");
  const result = await startApp();
  log("App started.");
  
  // Verify the app is running
  log("Verifying app is online...");
  try {
    const status = await getAppStatus();
    if (status && status.status === "online") {
      log(`App is online (PID: ${status.pid}, uptime: ${status.uptime ? Math.floor((Date.now() - status.uptime) / 1000) + "s" : "N/A"})`);
    } else {
      log("Warning: App status could not be confirmed.");
    }
  } catch {
    log("Warning: Could not verify app status.");
  }
  
  log("Redeploy completed.");
  return result;
}

export async function startApp(): Promise<string> {
  // Look for ecosystem file in the workspace or deployed app
  const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
  const possiblePaths = [
    `/home/${userName}/Myapp/.pm2/ecosystem.config.js`,
    path.posix.join(APP_ROOT, "ecosystem.config.js")
  ];
  
  let ecoPath: string | undefined;
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) { ecoPath = p; break; }
  }
  
  if (!ecoPath) {
    // Try to start via PM2 process name directly
    try {
      const result = await runCmd("pm2", ["start", "nextapp"]);
      return result.stdout;
    } catch {
      throw new Error("No ecosystem file found. Deploy first.");
    }
  }
  
  const result = await runCmd("pm2", ["startOrReload", ecoPath, "--update-env"]);
  return result.stdout;
}

export async function stopApp(): Promise<string> {
  try {
    const result = await runCmd("pm2", ["stop", "nextapp"]);
    return result.stdout;
  } catch {
    return "App was not running.";
  }
}

export async function getAppStatus(): Promise<any> {
  try {
    const result = await runCmd("pm2", ["jlist"]);
    const list = JSON.parse(result.stdout);
    const app = list.find((p: any) => p.name === "nextapp" || p.name === "bundledws-app");
    if (!app) return { status: "stopped" };
    const status = app.pm2_env?.status;
    const isOnline = status === "online";
    return { 
      name: app.name, 
      status: status || "stopped", 
      pid: isOnline ? app.pid : undefined, 
      uptime: isOnline ? (app.pm2_env?.pm_uptime || undefined) : undefined, 
      cpu: isOnline ? app.monit?.cpu : undefined, 
      memory: isOnline ? app.monit?.memory : undefined,
      restartCount: app.pm2_env?.restart_time,
      version: app.pm2_env?.version
    };
  } catch {
    return { status: "stopped" };
  }
}

export async function getAppLogs(lines = 100): Promise<string> {
  // Try new name first, then old name
  for (const name of ["nextapp", "bundledws-app"]) {
    try {
      const result = await runCmd("pm2", ["logs", name, "--lines", String(lines), "--nostream"]);
      return result.stdout;
    } catch {}
  }
  return "No logs available.";
}

export async function getLogsSince(hours: number): Promise<string> {
  const since = Date.now() - hours * 60 * 60 * 1000;
  const sinceStr = new Date(since).toISOString();
  // Try to get PM2 logs, filter by time
  for (const name of ["nextapp", "bundledws-app"]) {
    try {
      const result = await runCmd("pm2", ["logs", name, "--lines", "5000", "--nostream"]);
      const lines = result.stdout.split("\n").filter(l => {
        // Try to parse PM2 log timestamp format
        const match = l.match(/^\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}/);
        if (match) return new Date(match[0]).getTime() >= since;
        return true; // Include lines without timestamps
      });
      return lines.join("\n");
    } catch {}
  }
  return "No logs available for the specified period.";
}

