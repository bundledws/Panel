import fs from "node:fs";
import path from "node:path";

export interface SecurityCheck {
  passed: boolean;
  issues: string[];
  warnings: string[];
  maliciousFiles: string[];
  dependencyCount: number;
  diskUsageMb: number;
}

const MALICIOUS_PATTERNS = [
  // Crypto miners — specific software/algorithm names
  /cryptonight/i,
  /cryptominer/i,
  /xmrig/i,
  /minerd/i,
  /coinhive/i,
  // Actual attack patterns
  /reverse.*shell/i,
  /bind.*shell/i,
  // Code obfuscation
  /eval\(atob/i,
  // Dangerous Node.js API usage (direct spawn/exec without sanitization)
  /child_process\.exec\s*\(/i,
  // Actual file read of .env (not process.env access)
  /fs\.readFileSync\(.*\.env/i,
];

const SUSPICIOUS_FILES = [
  /\.(exe|dll|so|dylib|bin)$/i,
  /^(crypt|mine|bot|xmr)/i,
];

const SUSPICIOUS_SCRIPTS = [
  /curl.*\|.*(?:bash|sh)/,
  /wget.*\|.*(?:bash|sh)/,
  /chmod\s+\+x/,
  /\/dev\/tcp\//,
  /\/dev\/udp\//,
];

const MAX_FILES_TO_SCAN = 5000;
const MAX_FILE_READ_KB = 100; // only read first 100KB of each script file

/** Yield to event loop every N iterations to avoid blocking */
function yieldToLoop(): Promise<void> {
  return new Promise(r => setImmediate(r));
}

async function walkDirectoryAsync(dir: string, callback: (filePath: string) => Promise<void>): Promise<void> {
  let count = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const currentDir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules") continue;
      if (entry.name.startsWith(".") && entry.name !== ".env") continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        count++;
        if (count > MAX_FILES_TO_SCAN) return;
        await callback(fullPath);
        if (count % 50 === 0) await yieldToLoop();
      }
    }
  }
}

async function calculateDiskUsage(dir: string): Promise<number> {
  let total = 0;
  const stack = [dir];
  while (stack.length > 0) {
    const currentDir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === "node_modules") continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        try {
          const stat = await fs.promises.stat(fullPath);
          total += stat.size;
        } catch {}
      }
    }
  }
  return Math.round(total / (1024 * 1024));
}

export async function runSecurityCheck(dir: string): Promise<SecurityCheck> {
  const issues: string[] = [];
  const warnings: string[] = [];
  const maliciousFiles: string[] = [];
  let dependencyCount = 0;
  let diskUsageMb = 0;

  try {
    if (!fs.existsSync(dir)) {
      return { passed: false, issues: ["Directory does not exist"], warnings: [], maliciousFiles: [], dependencyCount: 0, diskUsageMb: 0 };
    }

    // Calculate disk usage (async)
    diskUsageMb = await calculateDiskUsage(dir);
    if (diskUsageMb > 500) {
      warnings.push(`Large project: ${diskUsageMb}MB (limit: 500MB)`);
    }

    // Check package.json
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(await fs.promises.readFile(pkgPath, "utf8"));

        // Count dependencies
        dependencyCount = Object.keys(pkg.dependencies || {}).length + Object.keys(pkg.devDependencies || {}).length;
        if (dependencyCount > 500) {
          warnings.push(`Large dependency count: ${dependencyCount} packages`);
        }

        // Check scripts for malicious patterns
        if (pkg.scripts) {
          for (const [name, script] of Object.entries(pkg.scripts)) {
            const scriptStr = String(script);
            for (const pattern of SUSPICIOUS_SCRIPTS) {
              if (pattern.test(scriptStr)) {
                issues.push(`Suspicious script "${name}": ${scriptStr.substring(0, 100)}`);
              }
            }
            for (const pattern of MALICIOUS_PATTERNS) {
              if (pattern.test(scriptStr)) {
                issues.push(`Malicious pattern in script "${name}": ${pattern}`);
              }
            }
          }
        }

        // Check for known malicious dependency names
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [depName] of Object.entries(allDeps)) {
          for (const pattern of MALICIOUS_PATTERNS) {
            if (pattern.test(depName)) {
              issues.push(`Suspicious dependency: ${depName}`);
            }
          }
        }
      } catch {}
    }

    // Walk directory for suspicious files (async with yield points)
    await walkDirectoryAsync(dir, async (filePath) => {
      const relative = path.relative(dir, filePath);
      const ext = path.extname(filePath).toLowerCase();

      // Check for suspicious file extensions
      for (const pattern of SUSPICIOUS_FILES) {
        if (pattern.test(relative)) {
          maliciousFiles.push(relative);
          return;
        }
      }

      // Check for hidden files with secrets (read first 2KB)
      if (relative === ".env" || relative.endsWith("/.env") || relative === ".env.local") {
        try {
          const buf = Buffer.alloc(2048);
          const fd = await fs.promises.open(filePath, "r");
          try {
            const { bytesRead } = await fd.read(buf, 0, 2048, 0);
            const content = buf.toString("utf8", 0, bytesRead);
            if (/password|secret|token|key|passwd|credential/i.test(content)) {
              warnings.push(`File may contain secrets: ${relative}`);
            }
          } finally { await fd.close(); }
        } catch {}
        return;
      }

      // Check for malicious patterns in JS/TS files (read only first 100KB)
      if (ext === ".js" || ext === ".jsx" || ext === ".ts" || ext === ".tsx") {
        try {
          const buf = Buffer.alloc(MAX_FILE_READ_KB * 1024);
          const fd = await fs.promises.open(filePath, "r");
          try {
            const { bytesRead } = await fd.read(buf, 0, MAX_FILE_READ_KB * 1024, 0);
            const content = buf.toString("utf8", 0, bytesRead);
            for (const pattern of MALICIOUS_PATTERNS) {
              if (pattern.test(content)) {
                issues.push(`Malicious pattern found in ${relative}`);
                break;
              }
            }
          } finally { await fd.close(); }
        } catch {}
      }
    });

    const passed = issues.length === 0;
    return { passed, issues, warnings, maliciousFiles, dependencyCount, diskUsageMb };
  } catch (err: any) {
    return { passed: false, issues: [`Security check error: ${err.message}`], warnings: [], maliciousFiles: [], dependencyCount: 0, diskUsageMb: 0 };
  }
}
