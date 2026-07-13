import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Auto-detect data directory relative to this module's location
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.resolve(__dirname, "..");
const DATA_DIR = path.join(APP_DIR, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");

interface StoredUser {
  id: string;
  email: string;
  passwordHash: string;
  role: "customer" | "admin";
  suspendedAt: string | null;
  createdAt: string;
}

interface StoredSession {
  id: string;
  userId: string;
  tokenHash: string;
  csrfToken: string;
  expiresAt: string;
  createdAt: string;
}

// Domain-related types (re-exported from domain-store for store persistence)
interface StoredDomain {
  id: string;
  customerId: string;
  domain: string;
  mode: "customer_dns" | "managed_dns";
  state: string;
  previousState: string | null;
  dnsProvider: string | null;
  dnsZoneId: string | null;
  dnsRecordIds: string[];
  dnsVerificationAttempts: number;
  dnsLastVerifiedAt: string | null;
  dnsExpectedIp: string;
  proxyStatus: string;
  certChallengeType: string | null;
  certSerial: string | null;
  certIssuer: string | null;
  certNotBefore: string | null;
  certNotAfter: string | null;
  certFingerprint: string | null;
  certPath: string | null;
  keyPath: string | null;
  nginxConfigHash: string | null;
  nginxConfigPath: string | null;
  lastKnownGoodConfig: string | null;
  rollbackState: string | null;
  createdAt: string;
  updatedAt: string;
  activatedAt: string | null;
  failedAt: string | null;
  failureReason: string | null;
  retryCount: number;
  maxRetries: number;
}

interface StoredAuditEvent {
  id: string;
  domainId: string;
  action: string;
  actor: string;
  fromState: string | null;
  toState: string | null;
  metadata: Record<string, any>;
  timestamp: string;
  ip: string;
}

interface StoredAcmeOrder {
  id: string;
  domainId: string;
  challengeType: "http-01" | "dns-01";
  orderUrl: string | null;
  status: string;
  expiresAt: string | null;
  challengeToken: string | null;
  challengeKeyAuth: string | null;
  validatedAt: string | null;
  error: string | null;
}

interface StoredDnsVerification {
  id: string;
  domainId: string;
  resolvedIps: string[];
  expectedIp: string;
  match: boolean;
  checkedAt: string;
  ttl: number | null;
}

interface StoredCertificateRenewal {
  id: string;
  domainId: string;
  status: string;
  lastRenewalAt: string | null;
  nextRenewalAt: string;
  renewalAttempts: number;
  lastError: string | null;
}

interface StoreData {
  users: StoredUser[];
  sessions: StoredSession[];
  domains: StoredDomain[];
  auditEvents: StoredAuditEvent[];
  acmeOrders: StoredAcmeOrder[];
  dnsVerifications: StoredDnsVerification[];
  certificateRenewals: StoredCertificateRenewal[];
}

let data: StoreData = {
  users: [],
  sessions: [],
  domains: [],
  auditEvents: [],
  acmeOrders: [],
  dnsVerifications: [],
  certificateRenewals: [],
};

// Map-based indexes for O(1) lookups — rebuilt on load(), maintained on mutations
let usersByEmail = new Map<string, StoredUser>();
let usersById = new Map<string, StoredUser>();
let sessionsByHash = new Map<string, StoredSession>();
let domainsById = new Map<string, StoredDomain>();
let domainsByDomain = new Map<string, StoredDomain>();
let acmeOrdersByDomainId = new Map<string, StoredAcmeOrder>();
let certificateRenewalsByDomainId = new Map<string, StoredCertificateRenewal>();

function rebuildIndexes(): void {
  usersByEmail = new Map(data.users.map(u => [u.email, u]));
  usersById = new Map(data.users.map(u => [u.id, u]));
  sessionsByHash = new Map(data.sessions.map(s => [s.tokenHash, s]));
  domainsById = new Map(data.domains.map(d => [d.id, d]));
  domainsByDomain = new Map(data.domains.map(d => [d.domain, d]));
  acmeOrdersByDomainId = new Map(data.acmeOrders.map(o => [o.domainId, o]));
  certificateRenewalsByDomainId = new Map(data.certificateRenewals.map(r => [r.domainId, r]));
}

let loaded = false;

function ensureDir(): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function load(): void {
  if (loaded) return;
  ensureDir();
  if (fs.existsSync(DATA_FILE)) {
    try {
      const raw = fs.readFileSync(DATA_FILE, "utf8");
      const parsed = JSON.parse(raw);
      // Gracefully handle old data that may have the multi-entity format
      data = {
        users: parsed.users || [],
        sessions: parsed.sessions || [],
        domains: parsed.domains || [],
        auditEvents: parsed.auditEvents || [],
        acmeOrders: parsed.acmeOrders || [],
        dnsVerifications: parsed.dnsVerifications || [],
        certificateRenewals: parsed.certificateRenewals || [],
      };
    } catch {
      data = { users: [], sessions: [], domains: [], auditEvents: [], acmeOrders: [], dnsVerifications: [], certificateRenewals: [] };
    }
  }
  rebuildIndexes();
  loaded = true;
}

let saveTimeout: ReturnType<typeof setTimeout> | null = null;
let writeQueue: Promise<void> = Promise.resolve();

function flushSave(): Promise<void> {
  const task = async () => {
    if (saveTimeout) { clearTimeout(saveTimeout); saveTimeout = null; }
    // Filter expired sessions before persisting (passive cleanup)
    const now = Date.now();
    data.sessions = data.sessions.filter(s => new Date(s.expiresAt).getTime() > now);
    ensureDir();
    const tmp = DATA_FILE + ".tmp." + Date.now();
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
    fs.renameSync(tmp, DATA_FILE);
  };
  writeQueue = writeQueue.then(task, task);
  return writeQueue;
}

function save(): void {
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(flushSave, 100);
}

// Flush pending writes before process exits
process.on("beforeExit", () => writeQueue);

// === User operations ===
export function findUserByEmail(email: string): StoredUser | undefined {
  load();
  return usersByEmail.get(email.toLowerCase());
}

export function findUserById(id: string): StoredUser | undefined {
  load();
  return usersById.get(id);
}

export function createUser(user: StoredUser): void {
  load();
  data.users.push(user);
  usersByEmail.set(user.email, user);
  usersById.set(user.id, user);
  save();
}

export function hasAdmin(): boolean {
  load();
  for (const u of data.users) { if (u.role === "admin") return true; }
  return false;
}

// === Session operations ===
export function findSessionByTokenHash(tokenHash: string): StoredSession | undefined {
  load();
  const session = sessionsByHash.get(tokenHash);
  // Lazy eviction: if session expired, remove it and return undefined
  if (session && new Date(session.expiresAt).getTime() <= Date.now()) {
    data.sessions = data.sessions.filter(s => s.tokenHash !== tokenHash);
    sessionsByHash.delete(tokenHash);
    save();
    return undefined;
  }
  return session;
}

export function createSession(session: StoredSession): void {
  load();
  data.sessions.push(session);
  sessionsByHash.set(session.tokenHash, session);
  save();
}

export function deleteSession(tokenHash: string): void {
  load();
  data.sessions = data.sessions.filter(s => s.tokenHash !== tokenHash);
  sessionsByHash.delete(tokenHash);
  save();
}

// === Domain operations ===
export function findDomainById(id: string): StoredDomain | undefined {
  load();
  return domainsById.get(id);
}

export function findDomainByDomain(domain: string): StoredDomain | undefined {
  load();
  return domainsByDomain.get(domain.toLowerCase());
}

export function listDomains(customerId?: string): StoredDomain[] {
  load();
  if (customerId) return data.domains.filter(d => d.customerId === customerId);
  return [...data.domains];
}

export function createDomain(domain: StoredDomain): void {
  load();
  data.domains.push(domain);
  domainsById.set(domain.id, domain);
  domainsByDomain.set(domain.domain, domain);
  save();
}

export function updateDomain(domain: StoredDomain): void {
  load();
  // Update in array
  const idx = data.domains.findIndex(d => d.id === domain.id);
  if (idx !== -1) data.domains[idx] = domain;
  // Update indexes
  domainsById.set(domain.id, domain);
  domainsByDomain.set(domain.domain, domain);
  save();
}

export function deleteDomain(id: string): boolean {
  load();
  const domain = domainsById.get(id);
  if (!domain) return false;
  data.domains = data.domains.filter(d => d.id !== id);
  domainsById.delete(id);
  domainsByDomain.delete(domain.domain);
  save();
  return true;
}

// === Audit Event operations ===
export function createAuditEvent(event: StoredAuditEvent): void {
  load();
  data.auditEvents.push(event);
  // Keep only last 1000 audit events per domain to prevent unbounded growth
  const domainEvents = data.auditEvents.filter(e => e.domainId === event.domainId);
  if (domainEvents.length > 1000) {
    const toRemove = domainEvents.slice(0, domainEvents.length - 1000);
    const removeIds = new Set(toRemove.map(e => e.id));
    data.auditEvents = data.auditEvents.filter(e => !removeIds.has(e.id));
  }
  save();
}

export function listAuditEvents(domainId: string, limit = 50): StoredAuditEvent[] {
  load();
  return data.auditEvents
    .filter(e => e.domainId === domainId)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}

// === ACME Order operations ===
export function createAcmeOrder(order: StoredAcmeOrder): void {
  load();
  data.acmeOrders.push(order);
  acmeOrdersByDomainId.set(order.domainId, order);
  save();
}

export function updateAcmeOrder(id: string, updates: Partial<StoredAcmeOrder>): StoredAcmeOrder | undefined {
  load();
  const idx = data.acmeOrders.findIndex(o => o.id === id);
  if (idx === -1) return undefined;
  Object.assign(data.acmeOrders[idx], updates);
  acmeOrdersByDomainId.set(data.acmeOrders[idx].domainId, data.acmeOrders[idx]);
  save();
  return data.acmeOrders[idx];
}

export function findAcmeOrderByDomainId(domainId: string): StoredAcmeOrder | undefined {
  load();
  return acmeOrdersByDomainId.get(domainId);
}

// === DNS Verification operations ===
export function createDnsVerification(verification: StoredDnsVerification): void {
  load();
  data.dnsVerifications.push(verification);
  // Keep only last 100 per domain
  const domainVerifications = data.dnsVerifications.filter(v => v.domainId === verification.domainId);
  if (domainVerifications.length > 100) {
    const toRemove = domainVerifications.slice(0, domainVerifications.length - 100);
    const removeIds = new Set(toRemove.map(v => v.id));
    data.dnsVerifications = data.dnsVerifications.filter(v => !removeIds.has(v.id));
  }
  save();
}

export function listDnsVerifications(domainId: string, limit = 20): StoredDnsVerification[] {
  load();
  return data.dnsVerifications
    .filter(v => v.domainId === domainId)
    .sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime())
    .slice(0, limit);
}

// === Certificate Renewal operations ===
export function createCertificateRenewal(renewal: StoredCertificateRenewal): void {
  load();
  data.certificateRenewals.push(renewal);
  certificateRenewalsByDomainId.set(renewal.domainId, renewal);
  save();
}

export function updateCertificateRenewal(id: string, updates: Partial<StoredCertificateRenewal>): StoredCertificateRenewal | undefined {
  load();
  const idx = data.certificateRenewals.findIndex(r => r.id === id);
  if (idx === -1) return undefined;
  Object.assign(data.certificateRenewals[idx], updates);
  certificateRenewalsByDomainId.set(data.certificateRenewals[idx].domainId, data.certificateRenewals[idx]);
  save();
  return data.certificateRenewals[idx];
}

export function findCertificateRenewalByDomainId(domainId: string): StoredCertificateRenewal | undefined {
  load();
  return certificateRenewalsByDomainId.get(domainId);
}

// === Utility ===
export function getStats() {
  load();
  return {
    users: data.users.length,
    sessions: data.sessions.length,
    domains: data.domains.length,
    auditEvents: data.auditEvents.length,
    acmeOrders: data.acmeOrders.length,
    dnsVerifications: data.dnsVerifications.length,
    certificateRenewals: data.certificateRenewals.length,
  };
}
