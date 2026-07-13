import fs from "node:fs";
import path from "node:path";
import { runCmd } from "./cmd.js";

// ============================================================
// Certificate Automation — ACME via acme.sh
// ============================================================

const ACME_CHALLENGE_DIR = "/var/lib/letsencrypt";
const ACME_HOME = process.env.HOME || "/root";
const ACME_SH_DIR = path.join(ACME_HOME, ".acme.sh");
const ACME_BIN = path.join(ACME_SH_DIR, "acme.sh");
const CERT_STORAGE_DIR = "/etc/nginx/bundledws/acme";

export interface CertPaths {
  fullchain: string;
  privkey: string;
  chain: string;
}

export interface CertInfo {
  serial: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  fingerprint: string;
  subject: string;
}

export interface IssueResult {
  success: boolean;
  certPaths: CertPaths | null;
  certInfo: CertInfo | null;
  error?: string;
  output: string;
}

// ============================================================
// ACME Client Detection & Installation
// ============================================================

export function findAcmeSh(): boolean {
  return fs.existsSync(ACME_BIN);
}

export async function ensureAcmeSh(): Promise<boolean> {
  if (findAcmeSh()) return true;
  try {
    await runCmd("curl", ["-s", "https://get.acme.sh", "|", "sh"], undefined, 60000);
    return findAcmeSh();
  } catch {
    return false;
  }
}

// ============================================================
// Certificate Paths
// ============================================================

export function getCertStorageDir(domain: string): string {
  return path.join(CERT_STORAGE_DIR, domain);
}

export function getCertPaths(domain: string): CertPaths {
  const dir = getCertStorageDir(domain);
  return {
    fullchain: path.join(dir, "fullchain.pem"),
    privkey: path.join(dir, "privkey.pem"),
    chain: path.join(dir, "chain.pem"),
  };
}

/**
 * Find acme.sh certificate directory for a domain.
 * acme.sh stores certs at ~/.acme.sh/{domain}_ecc/ or ~/.acme.sh/{domain}/
 */
export function findAcmeCertDir(domain: string): string | null {
  const eccDir = path.join(ACME_SH_DIR, `${domain}_ecc`);
  const rsaDir = path.join(ACME_SH_DIR, domain);

  if (fs.existsSync(eccDir) && fs.existsSync(path.join(eccDir, "fullchain.cer"))) {
    return eccDir;
  }
  if (fs.existsSync(rsaDir) && fs.existsSync(path.join(rsaDir, "fullchain.cer"))) {
    return rsaDir;
  }
  return null;
}

// ============================================================
// Certificate Verification
// ============================================================

/**
 * Verify certificate files exist and are valid.
 * Returns parsed certificate info or throws.
 */
export async function verifyCertificate(certPath: string, keyPath: string): Promise<CertInfo> {
  if (!fs.existsSync(certPath)) throw new Error(`Certificate not found: ${certPath}`);
  if (!fs.existsSync(keyPath)) throw new Error(`Private key not found: ${keyPath}`);

  // Verify cert with openssl
  const verifyResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-checkend", "0"], undefined, 10000);
  if (verifyResult.exitCode !== 0) {
    throw new Error("Certificate verification failed: certificate is expired or invalid");
  }

  // Extract certificate details
  const subjectResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-subject"], undefined, 10000);
  const issuerResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-issuer"], undefined, 10000);
  const datesResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-dates"], undefined, 10000);
  const fingerprintResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-fingerprint", "-sha256"], undefined, 10000);
  const serialResult = await runCmd("openssl", ["x509", "-in", certPath, "-noout", "-serial"], undefined, 10000);

  // Verify key matches cert
  try {
    const keyModulus = await runCmd("openssl", ["pkey", "-in", keyPath, "-pubout", "-outform", "pem"], undefined, 10000);
    const certModulus = await runCmd("openssl", ["x509", "-in", certPath, "-pubkey", "-noout", "-outform", "pem"], undefined, 10000);
    if (keyModulus.stdout.trim() !== certModulus.stdout.trim()) {
      throw new Error("Certificate and private key do not match");
    }
  } catch (err: any) {
    if (err.message?.includes("do not match")) throw err;
    // If openssl commands fail, log but don't block
  }

  // Parse dates
  const notBefore = datesResult.stdout.match(/notBefore=(.+)/)?.[1]?.trim() || "";
  const notAfter = datesResult.stdout.match(/notAfter=(.+)/)?.[1]?.trim() || "";

  return {
    serial: serialResult.stdout.replace("serial=", "").trim(),
    issuer: issuerResult.stdout.replace("issuer=", "").trim(),
    notBefore,
    notAfter,
    fingerprint: fingerprintResult.stdout.replace("SHA256 Fingerprint=", "").replace(/:/g, "").trim(),
    subject: subjectResult.stdout.replace("subject=", "").trim(),
  };
}

// ============================================================
// HTTP-01 Certificate Issuance
// ============================================================

/**
 * Issue a certificate using HTTP-01 challenge.
 * Requires nginx to be configured with the ACME challenge location.
 */
export async function issueCertificateHttp01(
  domain: string,
  onLog?: (msg: string) => void
): Promise<IssueResult> {
  const log = (msg: string) => { if (onLog) onLog(msg); };
  const output: string[] = [];

  try {
    // Ensure acme.sh is installed
    if (!(await ensureAcmeSh())) {
      return { success: false, certPaths: null, certInfo: null, error: "acme.sh not installed", output: output.join("\n") };
    }

    // Ensure challenge directory exists
    fs.mkdirSync(ACME_CHALLENGE_DIR, { recursive: true });

    // Register account if needed
    log("Registering with Let's Encrypt...");
    try {
      await runCmd(ACME_BIN, ["--register-account", "-m", "noreply@bundledws.com", "--server", "letsencrypt"], undefined, 30000);
    } catch {
      // Account may already exist — that's fine
    }

    // Issue certificate via HTTP-01
    log(`Issuing certificate for ${domain} via HTTP-01...`);
    const wwwDomain = `www.${domain}`;
    const result = await runCmd(
      ACME_BIN,
      [
        "--issue",
        "-d", domain,
        "-d", wwwDomain,
        "--webroot", ACME_CHALLENGE_DIR,
        "--server", "letsencrypt",
        "--force", // Force renewal if cert exists
      ],
      undefined,
      120000,
      (msg: string) => { output.push(msg); log(msg); }
    );

    output.push(result.stdout);
    log("Certificate issued successfully.");

    // Find the acme.sh cert directory
    const acmeCertDir = findAcmeCertDir(domain);
    if (!acmeCertDir) {
      return { success: false, certPaths: null, certInfo: null, error: "Certificate directory not found after issuance", output: output.join("\n") };
    }

    // Copy certs to stable location
    const certPaths = await installCertificate(domain, acmeCertDir);

    // Verify the certificate
    const certInfo = await verifyCertificate(certPaths.fullchain, certPaths.privkey);
    log(`Certificate valid until: ${certInfo.notAfter}`);

    return { success: true, certPaths, certInfo, output: output.join("\n") };
  } catch (err: any) {
    const error = err.message || "Unknown error";
    log(`Certificate issuance failed: ${error}`);
    return { success: false, certPaths: null, certInfo: null, error, output: output.join("\n") };
  }
}

// ============================================================
// DNS-01 Certificate Issuance (for managed DNS / wildcards)
// ============================================================

/**
 * Issue a certificate using DNS-01 challenge via Cloudflare.
 * Requires CF_Token and CF_Zone_ID to be set in environment.
 */
export async function issueCertificateDns01(
  domain: string,
  cfToken: string,
  cfZoneId: string,
  onLog?: (msg: string) => void
): Promise<IssueResult> {
  const log = (msg: string) => { if (onLog) onLog(msg); };
  const output: string[] = [];

  try {
    // Ensure acme.sh is installed
    if (!(await ensureAcmeSh())) {
      return { success: false, certPaths: null, certInfo: null, error: "acme.sh not installed", output: output.join("\n") };
    }

    // Register account if needed
    log("Registering with Let's Encrypt...");
    try {
      await runCmd(ACME_BIN, ["--register-account", "-m", "noreply@bundledws.com", "--server", "letsencrypt"], undefined, 30000);
    } catch {}

    // Issue certificate via DNS-01
    log(`Issuing certificate for ${domain} via DNS-01 (Cloudflare)...`);
    const wwwDomain = `www.${domain}`;

    // Set Cloudflare credentials as environment variables
    const env = {
      CF_Token: cfToken,
      CF_Zone_ID: cfZoneId,
    };

    const result = await runCmd(
      ACME_BIN,
      [
        "--issue",
        "-d", domain,
        "-d", wwwDomain,
        "--dns", "dns_cf",
        "--server", "letsencrypt",
        "--force",
      ],
      undefined,
      180000, // DNS-01 can take longer due to propagation
      (msg: string) => { output.push(msg); log(msg); },
      env
    );

    output.push(result.stdout);
    log("Certificate issued successfully.");

    // Find the acme.sh cert directory
    const acmeCertDir = findAcmeCertDir(domain);
    if (!acmeCertDir) {
      return { success: false, certPaths: null, certInfo: null, error: "Certificate directory not found after issuance", output: output.join("\n") };
    }

    // Copy certs to stable location
    const certPaths = await installCertificate(domain, acmeCertDir);

    // Verify the certificate
    const certInfo = await verifyCertificate(certPaths.fullchain, certPaths.privkey);
    log(`Certificate valid until: ${certInfo.notAfter}`);

    return { success: true, certPaths, certInfo, output: output.join("\n") };
  } catch (err: any) {
    const error = err.message || "Unknown error";
    log(`Certificate issuance failed: ${error}`);
    return { success: false, certPaths: null, certInfo: null, error, output: output.join("\n") };
  }
}

// ============================================================
// Certificate Installation (copy from acme.sh to stable dir)
// ============================================================

/**
 * Copy certificate files from acme.sh directory to stable storage.
 */
export async function installCertificate(
  domain: string,
  acmeCertDir: string
): Promise<CertPaths> {
  const certPaths = getCertPaths(domain);
  const certDir = path.dirname(certPaths.fullchain);

  // Create cert directory
  fs.mkdirSync(certDir, { recursive: true });

  // Copy files from acme.sh
  const acmeFullchain = path.join(acmeCertDir, "fullchain.cer");
  const acmeKey = path.join(acmeCertDir, `${domain}.key`);
  const acmeChain = path.join(acmeCertDir, "chain.cer");

  if (fs.existsSync(acmeFullchain)) {
    fs.copyFileSync(acmeFullchain, certPaths.fullchain);
  }
  if (fs.existsSync(acmeKey)) {
    fs.copyFileSync(acmeKey, certPaths.privkey);
  }
  if (fs.existsSync(acmeChain)) {
    fs.copyFileSync(acmeChain, certPaths.chain);
  }

  // Set secure permissions
  try { fs.chmodSync(certPaths.privkey, 0o600); } catch {}
  try { fs.chmodSync(certPaths.fullchain, 0o644); } catch {}

  return certPaths;
}

// ============================================================
// Certificate Renewal
// ============================================================

/**
 * Renew a certificate using acme.sh.
 * Returns the result and new cert info.
 */
export async function renewCertificate(
  domain: string,
  onLog?: (msg: string) => void
): Promise<IssueResult> {
  const log = (msg: string) => { if (onLog) onLog(msg); };
  const output: string[] = [];

  try {
    if (!findAcmeSh()) {
      return { success: false, certPaths: null, certInfo: null, error: "acme.sh not installed", output: "" };
    }

    log(`Renewing certificate for ${domain}...`);

    const result = await runCmd(
      ACME_BIN,
      ["--renew", "-d", domain, "--server", "letsencrypt", "--force"],
      undefined,
      120000,
      (msg: string) => { output.push(msg); log(msg); }
    );

    output.push(result.stdout);

    // Find the acme.sh cert directory
    const acmeCertDir = findAcmeCertDir(domain);
    if (!acmeCertDir) {
      return { success: false, certPaths: null, certInfo: null, error: "Certificate directory not found after renewal", output: output.join("\n") };
    }

    // Reinstall certs
    const certPaths = await installCertificate(domain, acmeCertDir);

    // Verify
    const certInfo = await verifyCertificate(certPaths.fullchain, certPaths.privkey);
    log(`Certificate renewed. Valid until: ${certInfo.notAfter}`);

    return { success: true, certPaths, certInfo, output: output.join("\n") };
  } catch (err: any) {
    const error = err.message || "Unknown error";
    log(`Certificate renewal failed: ${error}`);
    return { success: false, certPaths: null, certInfo: null, error, output: output.join("\n") };
  }
}

// ============================================================
// Challenge Cleanup
// ============================================================

/**
 * Clean up ACME challenge files and temporary DNS records.
 */
export async function cleanupChallenge(domain: string): Promise<void> {
  // Clean up HTTP-01 challenge files
  const challengeDir = path.join(ACME_CHALLENGE_DIR, ".well-known", "acme-challenge");
  if (fs.existsSync(challengeDir)) {
    try {
      const files = fs.readdirSync(challengeDir);
      for (const file of files) {
        try { fs.unlinkSync(path.join(challengeDir, file)); } catch {}
      }
    } catch {}
  }

  // Clean up acme.sh temp files
  const domainDir = path.join(ACME_SH_DIR, domain);
  if (fs.existsSync(domainDir)) {
    try {
      const files = fs.readdirSync(domainDir);
      for (const file of files) {
        if (file.endsWith(".tmp") || file.includes("challenge")) {
          try { fs.unlinkSync(path.join(domainDir, file)); } catch {}
        }
      }
    } catch {}
  }
}

// ============================================================
// Rate Limit Aware Retry
// ============================================================

const BACKOFF_DELAYS = [60000, 300000, 900000, 3600000]; // 1min, 5min, 15min, 1hr

/**
 * Calculate backoff delay based on attempt number.
 * Returns delay in milliseconds.
 */
export function getBackoffDelay(attempt: number): number {
  if (attempt <= 0) return 0;
  const idx = Math.min(attempt - 1, BACKOFF_DELAYS.length - 1);
  return BACKOFF_DELAYS[idx];
}

/**
 * Check if we should retry based on error message and attempt count.
 * Returns true if retry is advisable.
 */
export function shouldRetry(error: string, attempt: number, maxRetries: number): boolean {
  if (attempt >= maxRetries) return false;

  // Don't retry on certain errors
  const nonRetryable = [
    "invalid domain",
    "invalid email",
    "rate limit exceeded", // Let's Encrypt rate limit — wait longer
    "could not validate",
    "dns problem",
  ];

  const lower = error.toLowerCase();
  for (const pattern of nonRetryable) {
    if (lower.includes(pattern)) {
      // For rate limits, we can retry but with longer backoff
      if (pattern === "rate limit exceeded" && attempt < 3) return true;
      return false;
    }
  }

  return true;
}

// ============================================================
// Renewal Scheduling
// ============================================================

/**
 * Calculate the next renewal date (30 days before expiry).
 */
export function calculateNextRenewal(notAfter: string): string {
  const expiry = new Date(notAfter);
  const renewal = new Date(expiry.getTime() - 30 * 24 * 60 * 60 * 1000);
  return renewal.toISOString();
}

/**
 * Check if a certificate needs renewal (within 30 days of expiry).
 */
export function needsRenewal(notAfter: string): boolean {
  const expiry = new Date(notAfter).getTime();
  const now = Date.now();
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;
  return (expiry - now) < thirtyDays;
}

/**
 * Check if a certificate is expired.
 */
export function isExpired(notAfter: string): boolean {
  return new Date(notAfter).getTime() <= Date.now();
}