import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { createToken, hashSecret } from "./env.js";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const CSRF_BYTES = 24;
export function createSessionSecrets() {
    const sessionToken = createToken(32);
    const csrfToken = createToken(CSRF_BYTES);
    return {
        sessionToken,
        tokenHash: hashSecret(sessionToken),
        csrfToken
    };
}
export function sessionExpiresAt() {
    return new Date(Date.now() + SESSION_TTL_MS);
}
// Password hashing with scrypt
const KEY_LENGTH = 64;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1 };
export async function hashPassword(password) {
    const salt = randomBytes(16).toString("hex");
    const derivedKey = await deriveKey(password, salt);
    return `${salt}:${derivedKey.toString("hex")}`;
}
export async function verifyPassword(password, stored) {
    const [salt, keyHex] = stored.split(":");
    if (!salt || !keyHex)
        return false;
    const derivedKey = await deriveKey(password, salt);
    const storedKey = Buffer.from(keyHex, "hex");
    if (derivedKey.length !== storedKey.length)
        return false;
    return timingSafeEqual(derivedKey, storedKey);
}
function deriveKey(password, salt) {
    return new Promise((resolve, reject) => {
        scrypt(password.normalize("NFKC"), salt, KEY_LENGTH, SCRYPT_OPTIONS, (err, key) => {
            if (err)
                reject(err);
            else
                resolve(key);
        });
    });
}
//# sourceMappingURL=auth.js.map