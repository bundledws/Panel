import { createHash, randomBytes } from "node:crypto";
export function readEnv(key) {
    const value = process.env[key];
    if (!value)
        throw new Error(`Missing required environment variable: ${key}`);
    return value;
}
export function readIntEnv(key, fallback) {
    const raw = process.env[key];
    if (!raw) {
        if (fallback !== undefined)
            return fallback;
        throw new Error(`Missing required environment variable: ${key}`);
    }
    const n = parseInt(raw, 10);
    if (Number.isNaN(n))
        throw new Error(`Invalid integer for ${key}: ${raw}`);
    return n;
}
export function hashSecret(secret) {
    return createHash("sha256").update(secret).digest("hex");
}
export function createToken(bytes = 32) {
    return randomBytes(bytes).toString("hex");
}
/**
 * Returns the canonical app deployment directory.
 * All panel code (API routes, pipeline, PM2 management) uses this path.
 * Before this helper existed, some routes hardcoded /home/root/Myapp
 * while others used /home/${userName}/Myapp — that inconsistency is
 * the path bug this function eliminates.
 */
export function getAppDir() {
    const userName = process.env.USER || process.env.LOGNAME || "ubuntu";
    return `/home/${userName}/Myapp`;
}
//# sourceMappingURL=env.js.map