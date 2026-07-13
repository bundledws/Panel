import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
// Auto-detect data directory relative to this module's location
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_DIR = path.resolve(__dirname, "..");
const DATA_DIR = path.join(APP_DIR, "data");
const DATA_FILE = path.join(DATA_DIR, "data.json");
let data = {
    users: [],
    sessions: [],
    domains: [],
    auditEvents: [],
    acmeOrders: [],
    dnsVerifications: [],
    certificateRenewals: [],
};
// Map-based indexes for O(1) lookups — rebuilt on load(), maintained on mutations
let usersByEmail = new Map();
let usersById = new Map();
let sessionsByHash = new Map();
let domainsById = new Map();
let domainsByDomain = new Map();
let acmeOrdersByDomainId = new Map();
let certificateRenewalsByDomainId = new Map();
function rebuildIndexes() {
    usersByEmail = new Map(data.users.map(u => [u.email, u]));
    usersById = new Map(data.users.map(u => [u.id, u]));
    sessionsByHash = new Map(data.sessions.map(s => [s.tokenHash, s]));
    domainsById = new Map(data.domains.map(d => [d.id, d]));
    domainsByDomain = new Map(data.domains.map(d => [d.domain, d]));
    acmeOrdersByDomainId = new Map(data.acmeOrders.map(o => [o.domainId, o]));
    certificateRenewalsByDomainId = new Map(data.certificateRenewals.map(r => [r.domainId, r]));
}
let loaded = false;
function ensureDir() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
function load() {
    if (loaded)
        return;
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
        }
        catch {
            data = { users: [], sessions: [], domains: [], auditEvents: [], acmeOrders: [], dnsVerifications: [], certificateRenewals: [] };
        }
    }
    rebuildIndexes();
    loaded = true;
}
let saveTimeout = null;
let writeQueue = Promise.resolve();
function flushSave() {
    const task = async () => {
        if (saveTimeout) {
            clearTimeout(saveTimeout);
            saveTimeout = null;
        }
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
function save() {
    if (saveTimeout)
        clearTimeout(saveTimeout);
    saveTimeout = setTimeout(flushSave, 100);
}
// Flush pending writes before process exits
process.on("beforeExit", () => writeQueue);
// === User operations ===
export function findUserByEmail(email) {
    load();
    return usersByEmail.get(email.toLowerCase());
}
export function findUserById(id) {
    load();
    return usersById.get(id);
}
export function createUser(user) {
    load();
    data.users.push(user);
    usersByEmail.set(user.email, user);
    usersById.set(user.id, user);
    save();
}
export function hasAdmin() {
    load();
    for (const u of data.users) {
        if (u.role === "admin")
            return true;
    }
    return false;
}
// === Session operations ===
export function findSessionByTokenHash(tokenHash) {
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
export function createSession(session) {
    load();
    data.sessions.push(session);
    sessionsByHash.set(session.tokenHash, session);
    save();
}
export function deleteSession(tokenHash) {
    load();
    data.sessions = data.sessions.filter(s => s.tokenHash !== tokenHash);
    sessionsByHash.delete(tokenHash);
    save();
}
// === Domain operations ===
export function findDomainById(id) {
    load();
    return domainsById.get(id);
}
export function findDomainByDomain(domain) {
    load();
    return domainsByDomain.get(domain.toLowerCase());
}
export function listDomains(customerId) {
    load();
    if (customerId)
        return data.domains.filter(d => d.customerId === customerId);
    return [...data.domains];
}
export function createDomain(domain) {
    load();
    data.domains.push(domain);
    domainsById.set(domain.id, domain);
    domainsByDomain.set(domain.domain, domain);
    save();
}
export function updateDomain(domain) {
    load();
    // Update in array
    const idx = data.domains.findIndex(d => d.id === domain.id);
    if (idx !== -1)
        data.domains[idx] = domain;
    // Update indexes
    domainsById.set(domain.id, domain);
    domainsByDomain.set(domain.domain, domain);
    save();
}
export function deleteDomain(id) {
    load();
    const domain = domainsById.get(id);
    if (!domain)
        return false;
    data.domains = data.domains.filter(d => d.id !== id);
    domainsById.delete(id);
    domainsByDomain.delete(domain.domain);
    save();
    return true;
}
// === Audit Event operations ===
export function createAuditEvent(event) {
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
export function listAuditEvents(domainId, limit = 50) {
    load();
    return data.auditEvents
        .filter(e => e.domainId === domainId)
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);
}
// === ACME Order operations ===
export function createAcmeOrder(order) {
    load();
    data.acmeOrders.push(order);
    acmeOrdersByDomainId.set(order.domainId, order);
    save();
}
export function updateAcmeOrder(id, updates) {
    load();
    const idx = data.acmeOrders.findIndex(o => o.id === id);
    if (idx === -1)
        return undefined;
    Object.assign(data.acmeOrders[idx], updates);
    acmeOrdersByDomainId.set(data.acmeOrders[idx].domainId, data.acmeOrders[idx]);
    save();
    return data.acmeOrders[idx];
}
export function findAcmeOrderByDomainId(domainId) {
    load();
    return acmeOrdersByDomainId.get(domainId);
}
// === DNS Verification operations ===
export function createDnsVerification(verification) {
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
export function listDnsVerifications(domainId, limit = 20) {
    load();
    return data.dnsVerifications
        .filter(v => v.domainId === domainId)
        .sort((a, b) => new Date(b.checkedAt).getTime() - new Date(a.checkedAt).getTime())
        .slice(0, limit);
}
// === Certificate Renewal operations ===
export function createCertificateRenewal(renewal) {
    load();
    data.certificateRenewals.push(renewal);
    certificateRenewalsByDomainId.set(renewal.domainId, renewal);
    save();
}
export function updateCertificateRenewal(id, updates) {
    load();
    const idx = data.certificateRenewals.findIndex(r => r.id === id);
    if (idx === -1)
        return undefined;
    Object.assign(data.certificateRenewals[idx], updates);
    certificateRenewalsByDomainId.set(data.certificateRenewals[idx].domainId, data.certificateRenewals[idx]);
    save();
    return data.certificateRenewals[idx];
}
export function findCertificateRenewalByDomainId(domainId) {
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
//# sourceMappingURL=store.js.map