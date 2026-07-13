import { spawn } from "node:child_process";
import process from "node:process";

export type CmdResult = { stdout: string; stderr: string; exitCode: number };

/**
 * Run a command with spawn, capturing stdout/stderr.
 * Resolves with CmdResult on exit code 0.
 * Rejects with error message on non-zero exit.
 */
export function runCmd(
  command: string,
  args: string[],
  cwd?: string,
  timeout?: number,
  onLog?: (msg: string) => void,
  env?: Record<string, string>
): Promise<CmdResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      cwd,
      timeout: timeout || 30000,
      env: env ? { ...process.env, ...env } : undefined,
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    child.stdout.on("data", (c: Buffer) => {
      stdout.push(c);
      if (onLog) onLog(c.toString("utf8"));
    });

    child.stderr.on("data", (c: Buffer) => {
      stderr.push(c);
      if (onLog) onLog(c.toString("utf8"));
    });

    child.on("error", (err) => reject(new Error(`Failed to spawn ${command}: ${err.message}`)));

    child.on("close", (code) => {
      const out = Buffer.concat(stdout).toString("utf8").trim();
      const err = Buffer.concat(stderr).toString("utf8").trim();
      if (code !== 0) reject(new Error(err || out || `${command} exited with code ${code}`));
      else resolve({ stdout: out, stderr: err, exitCode: code ?? 0 });
    });
  });
}
