import { createToken } from "./env.js";
import * as store from "./store.js";

// ============================================================
// Types
// ============================================================

export type DomainMode = "customer_dns" | "managed_dns";
export type DnsProvider = "cloudflare";
export type ProxyStatus = "dns-only" | "proxied" | "unknown";

export type DomainState =
  | "draft"
  | "dns_pending"
  | "dns_verified"
  | "config_written"
  | "challenge_ready"
  | "certificate_issuing"
  | "certificate_installed"
  | "https_active"
  | "renewal_scheduled"
  | "active"
  | "failed"
  | "rolled_back";

export interface Domain {
  id: string;
  customerId: string;
  domain: string;
  mode: DomainMode;

  // State machine
  state: DomainState;
  previousState: DomainState | null;

  // DNS
  dnsProvider: DnsProvider | null;
  dnsZoneId: string | null;
  dnsRecordIds: string[];
  dnsVerificationAttempts: number;
  dnsLastVerifiedAt: string | null;
  dnsExpectedIp: string;
  proxyStatus: ProxyStatus;
  certChallengeType: "http-01" | "dns-01" | null;

  // Certificate
  certSerial: string | null;
  certIssuer: string | null;
  certNotBefore: string | null;
  certNotAfter: string | null;
  certFingerprint: string | null;
  certPath: string | null;
  keyPath: string | null;

  // Nginx
  nginxConfigHash: string | null;
  nginxConfigPath: string | null;

  // Rollback
  lastKnownGoodConfig: string | null;
  rollbackState: DomainState | null;

  // Timestamps
  createdAt: string;
  updatedAt: string;
  activatedAt: string | null;
  failedAt: string | null;
  failureReason: string | null;

  // Retry
  retryCount: number;
  maxRetries: number;
}

export interface AuditEvent {
  id: string;
  domainId: string;
  action: string;
  actor: string;
  fromState: DomainState | null;
  toState: DomainState | null;
  metadata: Record<string, any>;
  timestamp: string;
  ip: string;
}

export interface AcmeOrder {
  id: string;
  domainId: string;
  challengeType: "http-01" | "dns-01";
  orderUrl: string | null;
  status: "pending" | "processing" | "valid" | "invalid";
  expiresAt: string | null;
  challengeToken: string | null;
  challengeKeyAuth: string | null;
  validatedAt: string | null;
  error: string | null;
}

export interface DnsVerification {
  id: string;
  domainId: string;
  resolvedIps: string[];
  expectedIp: string;
  match: boolean;
  checkedAt: string;
  ttl: number | null;
}

export interface CertificateRenewal {
  id: string;
  domainId: string;
  status: "pending" | "renewing" | "success" | "failed";
  lastRenewalAt: string | null;
  nextRenewalAt: string;
  renewalAttempts: number;
  lastError: string | null;
}

// ============================================================
// State Machine — valid transitions
// ============================================================

const VALID_TRANSITIONS: Record<DomainState, DomainState[]> = {
  draft:              ["dns_pending", "failed"],
  dns_pending:        ["dns_verified", "failed"],
  dns_verified:       ["config_written", "failed"],
  config_written:     ["challenge_ready", "failed"],
  challenge_ready:    ["certificate_issuing", "failed"],
  certificate_issuing:["certificate_installed", "failed"],
  certificate_installed: ["https_active", "failed"],
  https_active:       ["renewal_scheduled", "failed", "dns_pending"],
  renewal_scheduled:  ["active", "failed"],
  active:             ["dns_pending", "failed"],
  failed:             ["dns_pending", "rolled_back", "draft"],
  rolled_back:        ["draft", "dns_pending"],
};

export function isValidTransition(from: DomainState, to: DomainState): boolean {
  const allowed = VALID_TRANSITIONS[from];
  if (!allowed) return false;
  return allowed.includes(to);
}

// ============================================================
// Domain CRUD
// ============================================================

export function createDomain(params: {
  customerId: string;
  domain: string;
  mode: DomainMode;
  dnsExpectedIp: string;
  dnsProvider?: DnsProvider;
  dnsZoneId?: string;
}): Domain {
  const now = new Date().toISOString();
  const domain: Domain = {
    id: createToken(16),
    customerId: params.customerId,
    domain: params.domain.toLowerCase(),
    mode: params.mode,
    state: "draft",
    previousState: null,
    dnsProvider: params.dnsProvider || null,
    dnsZoneId: params.dnsZoneId || null,
    dnsRecordIds: [],
    dnsVerificationAttempts: 0,
    dnsLastVerifiedAt: null,
    dnsExpectedIp: params.dnsExpectedIp,
    proxyStatus: "unknown",
    certChallengeType: null,
    certSerial: null,
    certIssuer: null,
    certNotBefore: null,
    certNotAfter: null,
    certFingerprint: null,
    certPath: null,
    keyPath: null,
    nginxConfigHash: null,
    nginxConfigPath: null,
    lastKnownGoodConfig: null,
    rollbackState: null,
    createdAt: now,
    updatedAt: now,
    activatedAt: null,
    failedAt: null,
    failureReason: null,
    retryCount: 0,
    maxRetries: 3,
  };
  store.createDomain(domain);
  return domain;
}

export function getDomain(id: string): Domain | undefined {
  const d = store.findDomainById(id);
  return d ? (d as unknown as Domain) : undefined;
}

export function getDomainByDomain(domain: string): Domain | undefined {
  const d = store.findDomainByDomain(domain.toLowerCase());
  return d ? (d as unknown as Domain) : undefined;
}

export function listDomains(customerId?: string): Domain[] {
  return store.listDomains(customerId) as unknown as Domain[];
}

export function updateDomainState(
  id: string,
  newState: DomainState,
  failureReason?: string
): Domain | undefined {
  const domain = store.findDomainById(id);
  if (!domain) return undefined;

  if (!isValidTransition(domain.state as DomainState, newState)) {
    throw new Error(
      `Invalid state transition: ${domain.state} → ${newState}`
    );
  }

  domain.previousState = domain.state;
  domain.state = newState;
  domain.updatedAt = new Date().toISOString();

  if (newState === "failed") {
    domain.failedAt = new Date().toISOString();
    domain.failureReason = failureReason || null;
    domain.retryCount++;
  }

  if (newState === "active" || newState === "https_active") {
    domain.activatedAt = domain.activatedAt || new Date().toISOString();
    domain.failureReason = null;
  }

  store.updateDomain(domain as any);
  return domain as unknown as Domain;
}

export function updateDomain(id: string, updates: Partial<Domain>): Domain | undefined {
  const domain = store.findDomainById(id);
  if (!domain) return undefined;
  Object.assign(domain, updates, { updatedAt: new Date().toISOString() });
  store.updateDomain(domain as any);
  return domain as unknown as Domain;
}

export function deleteDomain(id: string): boolean {
  return store.deleteDomain(id);
}

// ============================================================
// Audit Logging
// ============================================================

export function logAudit(event: {
  domainId: string;
  action: string;
  actor: string;
  fromState: DomainState | null;
  toState: DomainState | null;
  metadata?: Record<string, any>;
  ip?: string;
}): AuditEvent {
  const audit: AuditEvent = {
    id: createToken(16),
    domainId: event.domainId,
    action: event.action,
    actor: event.actor,
    fromState: event.fromState,
    toState: event.toState,
    metadata: event.metadata || {},
    timestamp: new Date().toISOString(),
    ip: event.ip || "unknown",
  };
  store.createAuditEvent(audit);
  return audit;
}

export function getAuditLogs(domainId: string, limit = 50): AuditEvent[] {
  return store.listAuditEvents(domainId, limit) as unknown as AuditEvent[];
}

// ============================================================
// ACME Order
// ============================================================

export function createAcmeOrder(params: {
  domainId: string;
  challengeType: "http-01" | "dns-01";
}): AcmeOrder {
  const order: AcmeOrder = {
    id: createToken(16),
    domainId: params.domainId,
    challengeType: params.challengeType,
    orderUrl: null,
    status: "pending",
    expiresAt: null,
    challengeToken: null,
    challengeKeyAuth: null,
    validatedAt: null,
    error: null,
  };
  store.createAcmeOrder(order);
  return order;
}

export function updateAcmeOrder(id: string, updates: Partial<AcmeOrder>): AcmeOrder | undefined {
  const result = store.updateAcmeOrder(id, updates as any);
  return result ? (result as unknown as AcmeOrder) : undefined;
}

export function getAcmeOrder(domainId: string): AcmeOrder | undefined {
  const result = store.findAcmeOrderByDomainId(domainId);
  return result ? (result as unknown as AcmeOrder) : undefined;
}

// ============================================================
// DNS Verification
// ============================================================

export function createDnsVerification(params: {
  domainId: string;
  resolvedIps: string[];
  expectedIp: string;
  match: boolean;
  ttl?: number | null;
}): DnsVerification {
  const verification: DnsVerification = {
    id: createToken(16),
    domainId: params.domainId,
    resolvedIps: params.resolvedIps,
    expectedIp: params.expectedIp,
    match: params.match,
    checkedAt: new Date().toISOString(),
    ttl: params.ttl || null,
  };
  store.createDnsVerification(verification);
  return verification;
}

export function getDnsVerifications(domainId: string, limit = 20): DnsVerification[] {
  return store.listDnsVerifications(domainId, limit);
}

// ============================================================
// Certificate Renewal
// ============================================================

export function createCertificateRenewal(domainId: string, nextRenewalAt: string): CertificateRenewal {
  const renewal: CertificateRenewal = {
    id: createToken(16),
    domainId,
    status: "pending",
    lastRenewalAt: null,
    nextRenewalAt,
    renewalAttempts: 0,
    lastError: null,
  };
  store.createCertificateRenewal(renewal);
  return renewal;
}

export function updateCertificateRenewal(id: string, updates: Partial<CertificateRenewal>): CertificateRenewal | undefined {
  const result = store.updateCertificateRenewal(id, updates as any);
  return result ? (result as unknown as CertificateRenewal) : undefined;
}

export function getCertificateRenewal(domainId: string): CertificateRenewal | undefined {
  const result = store.findCertificateRenewalByDomainId(domainId);
  return result ? (result as unknown as CertificateRenewal) : undefined;
}

// ============================================================
// Utility
// ============================================================

export function getDomainStats() {
  const domains = store.listDomains();
  const byState: Record<string, number> = {};
  for (const d of domains) {
    byState[d.state] = (byState[d.state] || 0) + 1;
  }
  return {
    total: domains.length,
    byState,
    active: domains.filter(d => d.state === "active" || d.state === "https_active").length,
    failed: domains.filter(d => d.state === "failed").length,
  };
}