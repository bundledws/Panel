import fs from "node:fs";
import path from "node:path";
import {
  type Domain,
  type DomainMode,
  type DnsProvider,
  type DomainState,
  createDomain,
  getDomain,
  getDomainByDomain,
  listDomains,
  updateDomainState,
  updateDomain,
  deleteDomain,
  logAudit,
  getAuditLogs,
  createAcmeOrder,
  updateAcmeOrder,
  getAcmeOrder,
  createDnsVerification,
  getDnsVerifications,
  createCertificateRenewal,
  updateCertificateRenewal,
  getCertificateRenewal,
} from "./domain-store.js";

import {
  validateDomain,
  verifyDnsResolution,
  pollDnsUntilVerified,
  generateDnsInstructions,
  isPrivateIp,
  detectProxyStatus,
  type DnsInstructions,
  type ProxyStatus,
} from "./domain-validate.js";

import {
  generatePerDomainConfig,
  writeDomainConfig,
  removeDomainConfig,
  writeDefaultServerBlock,
  listConfiguredDomains,
  withNginxLock,
  testNginxConfig,
  reloadNginx,
  ensureSnippets,
} from "./nginx.js";

import {
  issueCertificateHttp01,
  issueCertificateDns01,
  renewCertificate,
  verifyCertificate,
  cleanupChallenge,
  getBackoffDelay,
  shouldRetry,
  calculateNextRenewal,
  needsRenewal,
  isExpired,
  findAcmeCertDir,
  installCertificate,
  getCertPaths,
  type CertInfo,
  type CertPaths,
} from "./certificate.js";

const APP_PORT = 3000;
const ACME_CHALLENGE_DIR = "/var/lib/letsencrypt";

// ============================================================
// Domain Manager — State Machine Orchestrator
// ============================================================

export class DomainManager {
  private onLog: (domainId: string, msg: string) => void;

  constructor(onLog?: (domainId: string, msg: string) => void) {
    this.onLog = onLog || (() => {});
  }

  private log(domainId: string, msg: string): void {
    this.onLog(domainId, msg);
  }

  // ============================================================
  // Add Domain — Full Workflow
  // ============================================================

  /**
   * Add a new domain and begin the onboarding workflow.
   * State: draft → dns_pending
   */
  async addDomain(params: {
    customerId: string;
    domain: string;
    mode: DomainMode;
    publicIp: string;
    dnsProvider?: DnsProvider;
    dnsZoneId?: string;
  }): Promise<Domain> {
    const { customerId, domain: domainInput, mode, publicIp, dnsProvider, dnsZoneId } = params;

    // 1. Validate domain syntax
    const managedDomain = process.env.BWS_DOMAIN;
    const normalizedDomain = validateDomain(domainInput, managedDomain);

    // 2. Check for duplicates in our store
    const existing = getDomainByDomain(normalizedDomain);
    if (existing) {
      throw new Error(`Domain "${normalizedDomain}" is already configured`);
    }

    // Note: We no longer check nginx configs here — the store is the source of truth.
    // If a domain exists in nginx but not in the store, it's an orphaned config
    // that will be reconciled when the domains list is loaded.

    // 3. Validate public IP is not private
    if (isPrivateIp(publicIp)) {
      throw new Error(`Invalid public IP: ${publicIp} is a private IP address`);
    }

    // 5. Create domain record in draft state
    const domain = createDomain({
      customerId,
      domain: normalizedDomain,
      mode,
      dnsExpectedIp: publicIp,
      dnsProvider,
      dnsZoneId,
    });

    // 6. Log audit
    logAudit({
      domainId: domain.id,
      action: "domain.added",
      actor: customerId,
      fromState: null,
      toState: "draft",
      metadata: { domain: normalizedDomain, mode, publicIp },
    });

    // 7. Transition to DNS pending
    updateDomainState(domain.id, "dns_pending");

    this.log(domain.id, `Domain ${normalizedDomain} added. Waiting for DNS verification...`);

    return domain;
  }

  // ============================================================
  // Verify DNS
  // ============================================================

  /**
   * Trigger DNS verification. Returns a promise that resolves when
   * DNS is verified or polling is started.
   * State: dns_pending → dns_verified (or stays dns_pending)
   */
  async verifyDns(domainId: string): Promise<{
    verified: boolean;
    instructions?: DnsInstructions;
    error?: string;
    proxyStatus?: ProxyStatus;
  }> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");
    if (domain.state !== "dns_pending") {
      throw new Error(`Cannot verify DNS in state: ${domain.state}`);
    }

    // Check DNS resolution
    const check = await verifyDnsResolution(domain.domain, domain.dnsExpectedIp);

    // Record this verification attempt
    createDnsVerification({
      domainId: domain.id,
      resolvedIps: check.resolvedIps,
      expectedIp: domain.dnsExpectedIp,
      match: check.match,
      ttl: check.ttl,
    });

    // Update verification count and proxy status
    domain.dnsVerificationAttempts++;
    updateDomain(domain.id, {
      dnsVerificationAttempts: domain.dnsVerificationAttempts,
      proxyStatus: check.proxyStatus,
    });

    if (check.match) {
      // DNS is pointing correctly (either directly or via Cloudflare proxy)
      const proxyLabel = check.proxyStatus === "proxied" ? " (behind Cloudflare proxy)" : "";
      updateDomainState(domain.id, "dns_verified");
      updateDomain(domain.id, {
        dnsLastVerifiedAt: new Date().toISOString(),
        proxyStatus: check.proxyStatus,
      });

      logAudit({
        domainId: domain.id,
        action: "dns.verified",
        actor: "system",
        fromState: "dns_pending",
        toState: "dns_verified",
        metadata: {
          resolvedIps: check.resolvedIps,
          proxyStatus: check.proxyStatus,
        },
      });

      this.log(domain.id, `DNS verified for ${domain.domain}${proxyLabel}. Resolved to ${check.resolvedIps.join(", ")}`);
      return { verified: true, proxyStatus: check.proxyStatus };
    }

    // Generate instructions for the user
    const instructions = generateDnsInstructions(domain.domain, domain.dnsExpectedIp);

    // Check if resolved to private IP
    const privateIps = check.resolvedIps.filter(ip => isPrivateIp(ip));
    if (privateIps.length > 0) {
      const error = `Domain resolves to private IP: ${privateIps.join(", ")}. Point DNS to ${domain.dnsExpectedIp}`;
      this.log(domain.id, error);
      return { verified: false, instructions, error };
    }

    this.log(domain.id, `DNS not yet verified. Expected ${domain.dnsExpectedIp}, got [${check.resolvedIps.join(", ")}]`);
    return { verified: false, instructions };
  }

  // ============================================================
  // Start DNS Polling (long-running)
  // ============================================================

  /**
   * Start polling DNS until verified or timeout.
   * Updates state to dns_verified on success, failed on timeout.
   */
  async pollDns(domainId: string, maxAttempts = 30, intervalMs = 10000): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    this.log(domainId, `Polling DNS for ${domain.domain}...`);

    try {
      const result = await pollDnsUntilVerified(domain.domain, domain.dnsExpectedIp, maxAttempts, intervalMs);

      if (result.verified) {
        updateDomainState(domainId, "dns_verified");
        updateDomain(domainId, {
          dnsLastVerifiedAt: new Date().toISOString(),
          dnsVerificationAttempts: result.attempts,
        });

        logAudit({
          domainId,
          action: "dns.verified",
          actor: "system",
          fromState: "dns_pending",
          toState: "dns_verified",
          metadata: { attempts: result.attempts, lastCheck: result.lastCheck },
        });

        this.log(domainId, `DNS verified after ${result.attempts} attempts.`);
        return true;
      } else {
        // Max attempts reached
        updateDomainState(domainId, "failed", "DNS verification timed out. Check your DNS records.");
        this.log(domainId, `DNS verification timed out after ${maxAttempts} attempts.`);
        return false;
      }
    } catch (err: any) {
      updateDomainState(domainId, "failed", err.message);
      this.log(domainId, `DNS verification failed: ${err.message}`);
      return false;
    }
  }

  // ============================================================
  // Configure Nginx
  // ============================================================

  /**
   * Write nginx config for the domain.
   * State: dns_verified → config_written
   */
  async configureNginx(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    return withNginxLock(async () => {
      try {
        // Ensure snippets exist
        ensureSnippets();

        // Generate config (HTTP-only initially for ACME challenge)
        const config = generatePerDomainConfig(
          domain.domain,
          APP_PORT,
          null, // No cert yet
          null, // No key yet
          ACME_CHALLENGE_DIR
        );

        // Write config atomically
        const { configPath, configHash } = writeDomainConfig(domain.id, config);

        // Save the current config as "last known good" for rollback
        const oldConfig = domain.lastKnownGoodConfig;

        // Test nginx config
        const testResult = await testNginxConfig();
        if (!testResult.valid) {
          // Rollback: remove the newly written config
          removeDomainConfig(domain.id, false);
          throw new Error(`Nginx config test failed: ${testResult.output}`);
        }

        // Reload nginx
        const reloadResult = await reloadNginx();
        if (!reloadResult.ok) {
          removeDomainConfig(domain.id, false);
          if (oldConfig) {
            // Restore old config
            const oldPath = `/etc/nginx/bundledws/domains-available/domain-${domain.id}.conf`;
            fs.writeFileSync(oldPath, oldConfig, "utf8");
            await reloadNginx();
          }
          throw new Error(`Nginx reload failed: ${reloadResult.output}`);
        }

        updateDomainState(domainId, "config_written");
        updateDomain(domainId, {
          nginxConfigHash: configHash,
          nginxConfigPath: configPath,
          lastKnownGoodConfig: oldConfig || config, // Keep backup
        });

        logAudit({
          domainId,
          action: "nginx.config_written",
          actor: "system",
          fromState: "dns_verified",
          toState: "config_written",
          metadata: { configHash, configPath },
        });

        this.log(domainId, "Nginx config written and loaded.");
        return true;
      } catch (err: any) {
        updateDomainState(domainId, "failed", err.message);
        this.log(domainId, `Nginx config failed: ${err.message}`);
        return false;
      }
    });
  }

  // ============================================================
  // Issue Certificate
  // ============================================================

  /**
   * Issue a certificate for the domain.
   * State: config_written → challenge_ready → certificate_issuing → certificate_installed
   */
  async issueCertificate(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    try {
      // Transition to challenge_ready
      updateDomainState(domainId, "challenge_ready");

      // Create ACME order record
      const challengeType = domain.dnsProvider ? "dns-01" : "http-01";
      const order = createAcmeOrder({
        domainId: domain.id,
        challengeType,
      });

      this.log(domainId, `Starting certificate issuance via ${challengeType}...`);

      // Clean up any previous challenges
      await cleanupChallenge(domain.domain);

      // Transition to issuing
      updateDomainState(domainId, "certificate_issuing");
      updateAcmeOrder(order.id, { status: "processing" });

      // Determine challenge type based on proxy status and mode
      // Proxied domains MUST use DNS-01 (HTTP-01 fails behind Cloudflare proxy)
      // DNS-only domains can use HTTP-01 (simpler, no API token needed)
      let effectiveChallengeType = challengeType;
      if (domain.proxyStatus === "proxied" && challengeType === "http-01") {
        effectiveChallengeType = "dns-01";
        this.log(domainId, "Domain is behind Cloudflare proxy — switching to DNS-01 certificate validation");
      }

      // Issue based on mode
      let result;
      if (effectiveChallengeType === "dns-01") {
        // DNS-01 — try Cloudflare token first, then fall back to manual DNS
        let cfToken: string | null = null;
        let cfZoneId: string | null = domain.dnsZoneId;

        if (domain.dnsProvider === "cloudflare" || domain.proxyStatus === "proxied") {
          // Try to get Cloudflare token from encrypted storage
          try {
            const { readAndDecrypt } = await import("./crypto.js");
            const machineId = await import("./crypto.js").then(m => m.readMachineId());
            const encryptedPath = path.join(process.cwd(), ".cf-encrypted");
            cfToken = readAndDecrypt(encryptedPath, machineId);
          } catch {
            cfToken = process.env.BWS_CF_TOKEN || null;
          }

          // If we don't have a zone ID but have a token, try to detect it
          if (cfToken && !cfZoneId) {
            try {
              const domainParts = domain.domain.split(".");
              const apexDomain = domainParts.slice(-2).join(".");
              const zoneResp = await fetch(
                `https://api.cloudflare.com/client/v4/zones?name=${apexDomain}`,
                { headers: { Authorization: `Bearer ${cfToken}` } }
              );
              const zoneData = await zoneResp.json() as any;
              if (zoneData.success && zoneData.result?.length > 0) {
                cfZoneId = zoneData.result[0].id;
                updateDomain(domainId, { dnsZoneId: cfZoneId });
              }
            } catch {}
          }
        }

        if (cfToken && cfZoneId) {
          // DNS-01 with Cloudflare API
          result = await issueCertificateDns01(
            domain.domain,
            cfToken,
            cfZoneId,
            (msg) => this.log(domainId, msg)
          );
        } else {
          // DNS-01 without Cloudflare API — use acme.sh manual DNS mode
          // This requires the user to add a TXT record manually
          this.log(domainId, "No Cloudflare API token available. Using manual DNS-01 mode.");
          this.log(domainId, "You will need to add a TXT record to your DNS zone to complete validation.");
          result = await issueCertificateHttp01(
            domain.domain,
            (msg) => this.log(domainId, msg)
          );
          // If HTTP-01 fails behind proxy, try DNS-01 with manual hook
          if (!result.success) {
            this.log(domainId, "HTTP-01 failed (likely behind proxy). Attempting DNS-01 with manual challenge...");
            result = await issueCertificateDns01(
              domain.domain,
              "", // empty token triggers manual mode
              "",
              (msg) => this.log(domainId, msg)
            );
          }
        }
      } else {
        // HTTP-01 (for DNS-only domains)
        result = await issueCertificateHttp01(
          domain.domain,
          (msg) => this.log(domainId, msg)
        );
      }

      // Store the challenge type used for renewal
      updateDomain(domainId, { certChallengeType: effectiveChallengeType as "http-01" | "dns-01" });

      if (result.success && result.certPaths && result.certInfo) {
        // Update ACME order
        updateAcmeOrder(order.id, {
          status: "valid",
          validatedAt: new Date().toISOString(),
        });

        // Update domain with certificate info
        updateDomain(domainId, {
          certSerial: result.certInfo.serial,
          certIssuer: result.certInfo.issuer,
          certNotBefore: result.certInfo.notBefore,
          certNotAfter: result.certInfo.notAfter,
          certFingerprint: result.certInfo.fingerprint,
          certPath: result.certPaths.fullchain,
          keyPath: result.certPaths.privkey,
        });

        // Transition to certificate_installed
        updateDomainState(domainId, "certificate_installed");

        logAudit({
          domainId,
          action: "certificate.issued",
          actor: "system",
          fromState: "certificate_issuing",
          toState: "certificate_installed",
          metadata: {
            serial: result.certInfo.serial,
            notAfter: result.certInfo.notAfter,
            issuer: result.certInfo.issuer,
          },
        });

        this.log(domainId, `Certificate issued. Valid until: ${result.certInfo.notAfter}`);

        // Now update nginx config with HTTPS
        return await this.enableHttps(domainId);
      } else {
        updateAcmeOrder(order.id, {
          status: "invalid",
          error: result.error || "Unknown error",
        });
        throw new Error(result.error || "Certificate issuance failed");
      }
    } catch (err: any) {
      updateDomainState(domainId, "failed", err.message);
      this.log(domainId, `Certificate issuance failed: ${err.message}`);
      return false;
    }
  }

  // ============================================================
  // Enable HTTPS (update nginx config)
  // ============================================================

  /**
   * Update nginx config to enable HTTPS redirect and SSL.
   * State: certificate_installed → https_active
   */
  async enableHttps(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");
    if (!domain.certPath || !domain.keyPath) {
      throw new Error("Certificate not installed");
    }

    return withNginxLock(async () => {
      try {
        // Generate full HTTPS config
        const config = generatePerDomainConfig(
          domain.domain,
          APP_PORT,
          domain.certPath,
          domain.keyPath,
          ACME_CHALLENGE_DIR
        );

        // Save current config as backup before overwriting
        const currentConfigPath = path.join("/etc/nginx/bundledws/domains-available", `domain-${domain.id}.conf`);
        let backup: string | null = null;
        if (fs.existsSync(currentConfigPath)) {
          backup = fs.readFileSync(currentConfigPath, "utf8");
        }

        // Write updated config
        const { configHash } = writeDomainConfig(domain.id, config);

        // Test config
        const testResult = await testNginxConfig();
        if (!testResult.valid) {
          // Restore backup
          if (backup) {
            fs.writeFileSync(currentConfigPath, backup, "utf8");
          }
          throw new Error(`Nginx config test failed after certificate: ${testResult.output}`);
        }

        // Reload nginx
        const reloadResult = await reloadNginx();
        if (!reloadResult.ok) {
          if (backup) {
            fs.writeFileSync(currentConfigPath, backup, "utf8");
            await reloadNginx();
          }
          throw new Error(`Nginx reload failed after certificate: ${reloadResult.output}`);
        }

        updateDomainState(domainId, "https_active");
        updateDomain(domainId, {
          nginxConfigHash: configHash,
          lastKnownGoodConfig: backup || config,
        });

        logAudit({
          domainId,
          action: "https.enabled",
          actor: "system",
          fromState: "certificate_installed",
          toState: "https_active",
          metadata: { certPath: domain.certPath },
        });

        this.log(domainId, "HTTPS enabled. Domain is live.");
        return true;
      } catch (err: any) {
        this.log(domainId, `HTTPS enable failed: ${err.message}`);
        return false;
      }
    });
  }

  // ============================================================
  // Schedule Renewal
  // ============================================================

  /**
   * Schedule certificate renewal.
   * State: https_active → renewal_scheduled → active
   */
  async scheduleRenewal(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");
    if (!domain.certNotAfter) throw new Error("Certificate expiry not set");

    try {
      const nextRenewal = calculateNextRenewal(domain.certNotAfter);

      const renewal = createCertificateRenewal(domainId, nextRenewal);

      updateDomainState(domainId, "renewal_scheduled");

      logAudit({
        domainId,
        action: "renewal.scheduled",
        actor: "system",
        fromState: "https_active",
        toState: "renewal_scheduled",
        metadata: { nextRenewal },
      });

      this.log(domainId, `Renewal scheduled for ${nextRenewal}`);

      // Transition to active
      updateDomainState(domainId, "active");
      return true;
    } catch (err: any) {
      updateDomainState(domainId, "failed", err.message);
      return false;
    }
  }

  // ============================================================
  // Check and Perform Renewal
  // ============================================================

  /**
   * Check if any domains need renewal and renew them.
   * Called periodically by a timer.
   */
  async checkRenewals(): Promise<string[]> {
    const domains = listDomains();
    const renewed: string[] = [];

    for (const domain of domains) {
      if (domain.state !== "active" && domain.state !== "https_active") continue;
      if (!domain.certNotAfter) continue;

      if (needsRenewal(domain.certNotAfter) || isExpired(domain.certNotAfter)) {
        this.log(domain.id, `Certificate needs renewal (expires: ${domain.certNotAfter})`);
        const result = await this.performRenewal(domain.id);
        if (result) renewed.push(domain.domain);
      }
    }

    return renewed;
  }

  /**
   * Perform certificate renewal for a specific domain.
   */
  async performRenewal(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) return false;

    const renewal = getCertificateRenewal(domainId);
    if (!renewal) return false;

    try {
      updateCertificateRenewal(renewal.id, { status: "renewing", renewalAttempts: renewal.renewalAttempts + 1 });

      // Detect current proxy status for renewal
      const currentProxyStatus = await detectProxyStatus(domain.domain);
      const wasProxied = currentProxyStatus === "proxied";
      const originalChallengeType = domain.certChallengeType;

      // Renew certificate using the appropriate method
      let result;
      if (wasProxied || originalChallengeType === "dns-01") {
        // Proxied or was issued via DNS-01 — use DNS-01 renewal
        this.log(domainId, "Using DNS-01 for renewal (domain is behind proxy or was issued via DNS-01)");

        let cfToken: string | null = null;
        let cfZoneId: string | null = domain.dnsZoneId;

        try {
          const { readAndDecrypt } = await import("./crypto.js");
          const machineId = await import("./crypto.js").then(m => m.readMachineId());
          const encryptedPath = path.join(process.cwd(), ".cf-encrypted");
          cfToken = readAndDecrypt(encryptedPath, machineId);
        } catch {
          cfToken = process.env.BWS_CF_TOKEN || null;
        }

        if (cfToken && cfZoneId) {
          result = await issueCertificateDns01(
            domain.domain,
            cfToken,
            cfZoneId,
            (msg) => this.log(domainId, msg)
          );
        } else {
          // Fall back to standard renewal (acme.sh handles the method)
          result = await renewCertificate(domain.domain, (msg) => this.log(domainId, msg));
        }
      } else {
        // DNS-only — use standard HTTP-01 renewal
        result = await renewCertificate(domain.domain, (msg) => this.log(domainId, msg));
      }

      if (result.success && result.certPaths && result.certInfo) {
        // Update domain record
        updateDomain(domainId, {
          certSerial: result.certInfo.serial,
          certIssuer: result.certInfo.issuer,
          certNotBefore: result.certInfo.notBefore,
          certNotAfter: result.certInfo.notAfter,
          certFingerprint: result.certInfo.fingerprint,
          certPath: result.certPaths.fullchain,
          keyPath: result.certPaths.privkey,
        });

        // Update nginx with new cert (reload if config has cert paths)
        // The cert paths are the same stable paths, just updated content
        // So we just reload nginx to pick up the new files
        const reloadResult = await reloadNginx();
        if (!reloadResult.ok) {
          this.log(domainId, `Nginx reload after renewal failed: ${reloadResult.output}`);
        }

        // Update renewal record
        const nextRenewal = calculateNextRenewal(result.certInfo.notAfter);
        updateCertificateRenewal(renewal.id, {
          status: "success",
          lastRenewalAt: new Date().toISOString(),
          nextRenewalAt: nextRenewal,
          renewalAttempts: renewal.renewalAttempts + 1,
          lastError: null,
        });

        logAudit({
          domainId,
          action: "certificate.renewed",
          actor: "system",
          fromState: "active",
          toState: "active",
          metadata: {
            serial: result.certInfo.serial,
            notAfter: result.certInfo.notAfter,
          },
        });

        this.log(domainId, `Certificate renewed. Valid until: ${result.certInfo.notAfter}`);
        return true;
      } else {
        throw new Error(result.error || "Renewal failed");
      }
    } catch (err: any) {
      updateCertificateRenewal(renewal.id, {
        status: "failed",
        lastError: err.message,
        renewalAttempts: renewal.renewalAttempts + 1,
      });

      // If this is the first failure, stay in active state (old cert still works)
      if (renewal.renewalAttempts >= 3) {
        updateDomainState(domainId, "failed", `Renewal failed after ${renewal.renewalAttempts + 1} attempts: ${err.message}`);
      }

      this.log(domainId, `Renewal failed: ${err.message}`);
      return false;
    }
  }

  // ============================================================
  // Retry Failed Domain
  // ============================================================

  /**
   * Retry a failed domain from its previous state.
   * State: failed → previous state
   */
  async retryDomain(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");
    if (domain.state !== "failed") throw new Error(`Cannot retry domain in state: ${domain.state}`);
    if (domain.retryCount >= domain.maxRetries) {
      throw new Error(`Max retries (${domain.maxRetries}) exceeded for this domain`);
    }

    // Determine the right state to retry from based on what we have
    let targetState: DomainState = "dns_pending";

    if (domain.nginxConfigHash) {
      targetState = "config_written";
    }
    if (domain.certPath && domain.keyPath && fs.existsSync(domain.certPath)) {
      targetState = "certificate_installed";
    }

    this.log(domainId, `Retrying from state: ${targetState}`);

    // Clear failure state
    updateDomainState(domainId, targetState);
    updateDomain(domainId, { failureReason: null });

    logAudit({
      domainId,
      action: "domain.retry",
      actor: "system",
      fromState: "failed",
      toState: targetState,
      metadata: { retryCount: domain.retryCount + 1 },
    });

    // Resume the workflow from the target state
    return this.resumeWorkflow(domainId);
  }

  // ============================================================
  // Rollback Domain
  // ============================================================

  /**
   * Rollback a domain to its previous state.
   * Restores nginx config, removes cert files if applicable.
   */
  async rollbackDomain(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    const previousState = domain.previousState || "draft";

    this.log(domainId, `Rolling back from ${domain.state} to ${previousState}...`);

    return withNginxLock(async () => {
      try {
        // Restore previous nginx config if it exists
        if (domain.lastKnownGoodConfig) {
          const configPath = path.join("/etc/nginx/bundledws/domains-available", `domain-${domain.id}.conf`);
          fs.writeFileSync(configPath, domain.lastKnownGoodConfig, "utf8");

          const testResult = await testNginxConfig();
          if (testResult.valid) {
            await reloadNginx();
          }
        } else {
          // No backup config — remove our config
          removeDomainConfig(domain.id, false);
          await reloadNginx();
        }

        // Update state
        updateDomainState(domainId, previousState === "failed" ? "draft" : previousState);
        updateDomain(domainId, { rollbackState: domain.state, failureReason: null, retryCount: 0 });

        logAudit({
          domainId,
          action: "domain.rolled_back",
          actor: "system",
          fromState: domain.state,
          toState: previousState,
          metadata: { rollbackState: domain.state },
        });

        this.log(domainId, `Rolled back to ${previousState}.`);
        return true;
      } catch (err: any) {
        this.log(domainId, `Rollback failed: ${err.message}`);
        return false;
      }
    });
  }

  // ============================================================
  // Remove Domain (Full Cleanup)
  // ============================================================

  /**
   * Remove a domain and clean up all associated resources.
   */
  async removeDomain(domainId: string, actor: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    return withNginxLock(async () => {
      try {
        // 1. Remove nginx config
        removeDomainConfig(domain.id, false);

        // 2. Reload nginx
        const testResult = await testNginxConfig();
        if (testResult.valid) {
          await reloadNginx();
        }

        // 3. Remove cert files
        if (domain.certPath) {
          const certDir = path.dirname(domain.certPath);
          try {
            fs.rmSync(certDir, { recursive: true, force: true });
          } catch {}
        }

        // 4. Log audit
        logAudit({
          domainId,
          action: "domain.removed",
          actor,
          fromState: domain.state,
          toState: null,
          metadata: { domain: domain.domain },
        });

        // 5. Delete from store
        deleteDomain(domainId);

        this.log(domainId, `Domain ${domain.domain} removed.`);
        return true;
      } catch (err: any) {
        this.log(domainId, `Remove failed: ${err.message}`);
        return false;
      }
    });
  }

  // ============================================================
  // Resume Workflow
  // ============================================================

  /**
   * Resume the domain onboarding workflow from the current state.
   * This is the main state machine executor.
   */
  async resumeWorkflow(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) return false;

    this.log(domainId, `Resuming workflow from state: ${domain.state}`);

    switch (domain.state) {
      case "draft":
      case "dns_pending":
        // Start DNS polling (non-blocking — returns quickly)
        return this.pollDns(domainId, 30, 10000);

      case "dns_verified":
        return this.configureNginx(domainId);

      case "config_written":
      case "challenge_ready":
        return this.issueCertificate(domainId);

      case "certificate_issuing":
        // Check if cert was actually issued (process may have restarted)
        if (domain.certPath && fs.existsSync(domain.certPath)) {
          return this.enableHttps(domainId);
        }
        return this.issueCertificate(domainId);

      case "certificate_installed":
        return this.enableHttps(domainId);

      case "https_active":
        return this.scheduleRenewal(domainId);

      case "renewal_scheduled":
        updateDomainState(domainId, "active");
        return true;

      case "active":
        return true; // Already active

      case "failed":
        return this.retryDomain(domainId);

      default:
        this.log(domainId, `Unknown state: ${domain.state}`);
        return false;
    }
  }

  // ============================================================
  // Health Check
  // ============================================================

  /**
   * Verify that an active domain is still properly configured.
   */
  async verifyHealth(domainId: string): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const domain = getDomain(domainId);
    if (!domain) return { healthy: false, issues: ["Domain not found"] };

    const issues: string[] = [];

    // 1. Check DNS still resolves correctly
    try {
      const dnsCheck = await verifyDnsResolution(domain.domain, domain.dnsExpectedIp);
      if (!dnsCheck.match) {
        issues.push(`DNS no longer resolves to ${domain.dnsExpectedIp}. Got: ${dnsCheck.resolvedIps.join(", ") || "nothing"}`);
      }
    } catch (err: any) {
      issues.push(`DNS check failed: ${err.message}`);
    }

    // 2. Check nginx config exists
    if (domain.nginxConfigPath) {
      if (!fs.existsSync(domain.nginxConfigPath)) {
        issues.push("Nginx config file is missing");
      }
    } else {
      issues.push("No nginx config path recorded");
    }

    // 3. Check certificate
    if (domain.certPath && domain.keyPath) {
      if (!fs.existsSync(domain.certPath)) {
        issues.push("Certificate file is missing");
      }
      if (!fs.existsSync(domain.keyPath)) {
        issues.push("Private key file is missing");
      }
      if (domain.certNotAfter && isExpired(domain.certNotAfter)) {
        issues.push(`Certificate expired on ${domain.certNotAfter}`);
      }
    }

    // 4. Check nginx is running
    try {
      const { runCmd } = await import("./cmd.js");
      const result = await runCmd("systemctl", ["is-active", "nginx"], undefined, 5000);
      if (result.stdout.trim() !== "active") {
        issues.push("Nginx is not running");
      }
    } catch {
      issues.push("Could not check nginx status");
    }

    return {
      healthy: issues.length === 0,
      issues,
    };
  }

  // ============================================================
  // Full Onboarding Orchestration (one-shot)
  // ============================================================

  /**
   * Run the complete domain onboarding workflow from start to finish.
   * This is an async function that may take a long time due to DNS polling.
   */
  async onboardDomain(domainId: string): Promise<boolean> {
    const domain = getDomain(domainId);
    if (!domain) throw new Error("Domain not found");

    this.log(domainId, `Starting full onboarding for ${domain.domain}...`);

    try {
      // Step 1: DNS verification (poll until verified or timeout)
      this.log(domainId, "Step 1: Verifying DNS...");
      const dnsOk = await this.pollDns(domainId, 30, 10000);
      if (!dnsOk) return false;

      // Step 2: Configure nginx
      this.log(domainId, "Step 2: Configuring nginx...");
      const nginxOk = await this.configureNginx(domainId);
      if (!nginxOk) return false;

      // Step 3: Issue certificate
      this.log(domainId, "Step 3: Issuing certificate...");
      const certOk = await this.issueCertificate(domainId);
      if (!certOk) return false;

      // Step 4: Schedule renewal
      this.log(domainId, "Step 4: Scheduling renewal...");
      const renewalOk = await this.scheduleRenewal(domainId);
      if (!renewalOk) return false;

      this.log(domainId, `✓ Domain ${domain.domain} is fully active!`);
      return true;
    } catch (err: any) {
      this.log(domainId, `Onboarding failed: ${err.message}`);
      updateDomainState(domainId, "failed", err.message);
      return false;
    }
  }
}