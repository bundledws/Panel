import { randomBytes, createHmac, createCipheriv, createDecipheriv } from "node:crypto";
import fs from "node:fs";

// ============================================================
// AES-256-GCM Encrypted Credential Storage
// Used to store Cloudflare API tokens at rest, tied to the
// VPS's unique machine ID. Token is decrypted just-in-time
// during cert renewal — never written to disk in plaintext.
// ============================================================

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12;  // GCM standard nonce
const SALT_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;
const MACHINE_ID_PATH = "/etc/machine-id";

export interface EncryptedBlob {
  salt: Buffer;      // 32 bytes — random per encryption
  iv: Buffer;        // 12 bytes — GCM nonce
  ciphertext: Buffer; // encrypted payload
  authTag: Buffer;   // 16 bytes — GCM authentication tag
}

export interface StoredCredential {
  encryptedPath: string; // path to the stored encrypted blob
}

// ============================================================
// Key Derivation — HKDF-SHA256 from machine-id + salt
// ============================================================

function deriveKey(machineId: string, salt: Buffer): Buffer {
  // Use HMAC-SHA256 as a simple KDF (HKDF without the expand step)
  // key = HMAC-SHA256(machineId, salt)
  return createHmac("sha256", machineId).update(salt).digest();
}

// ============================================================
// Read machine ID from /etc/machine-id
// ============================================================

export function readMachineId(): string {
  if (!fs.existsSync(MACHINE_ID_PATH)) {
    throw new Error(`Machine ID not found at ${MACHINE_ID_PATH}`);
  }
  return fs.readFileSync(MACHINE_ID_PATH, "utf8").trim();
}

// ============================================================
// Encrypt — AES-256-GCM
// Plaintext → random salt + random IV + ciphertext + auth tag
// ============================================================

export function encrypt(
  plaintext: string,
  machineId: string,
  salt?: Buffer
): EncryptedBlob {
  const keySalt = salt || randomBytes(SALT_LENGTH);
  const key = deriveKey(machineId, keySalt);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    salt: keySalt,
    iv,
    ciphertext,
    authTag,
  };
}

// ============================================================
// Decrypt — AES-256-GCM
// salt + iv + ciphertext + auth tag → plaintext
// ============================================================

export function decrypt(
  blob: EncryptedBlob,
  machineId: string
): string {
  const key = deriveKey(machineId, blob.salt);
  const decipher = createDecipheriv(ALGORITHM, key, blob.iv);
  decipher.setAuthTag(blob.authTag);

  const plaintext = Buffer.concat([
    decipher.update(blob.ciphertext),
    decipher.final(),
  ]);

  return plaintext.toString("utf8");
}

// ============================================================
// Serialize encrypted blob to binary format
// Layout: salt (32) || iv (12) || authTag (16) || ciphertext (rest)
// ============================================================

export function serializeBlob(blob: EncryptedBlob): Buffer {
  return Buffer.concat([blob.salt, blob.iv, blob.authTag, blob.ciphertext]);
}

// ============================================================
// Deserialize binary to encrypted blob
// ============================================================

export function deserializeBlob(data: Buffer): EncryptedBlob {
  if (data.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error("Invalid encrypted blob: too short");
  }
  let offset = 0;
  const salt = data.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const authTag = data.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;
  const ciphertext = data.subarray(offset);

  return { salt, iv, ciphertext, authTag };
}

// ============================================================
// Encrypt and write to file (convenience for install.sh usage)
// ============================================================

export function encryptAndStore(
  plaintext: string,
  outputPath: string,
  machineId: string
): void {
  const blob = encrypt(plaintext, machineId);
  const data = serializeBlob(blob);
  fs.writeFileSync(outputPath, data, { mode: 0o600 });
}

// ============================================================
// Read from file and decrypt (convenience for renewal)
// ============================================================

export function readAndDecrypt(
  inputPath: string,
  machineId: string
): string {
  const data = fs.readFileSync(inputPath);
  const blob = deserializeBlob(data);
  return decrypt(blob, machineId);
}
