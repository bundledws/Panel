import { createToken } from "./env.js";
import * as store from "./store.js";
// ============================================================
// State Machine — valid transitions
// ============================================================
const VALID_TRANSITIONS = {
    draft: ["dns_pending", "failed"],
    dns_pending: ["dns_verified", "failed"],
    dns_verified: ["config_written", "failed"],
    config_written: ["challenge_ready", "failed"],
    challenge_ready: ["certificate_issuing", "failed"],
    certificate_issuing: ["certificate_installed", "failed"],
    certificate_installed: ["https_active", "failed"],
    https_active: ["renewal_scheduled", "failed", "dns_pending"],
    renewal_scheduled: ["active", "failed"],
    active: ["dns_pending", "failed"],
    failed: ["dns_pending", "rolled_back", "draft"],
    rolled_back: ["draft", "dns_pending"],
};
export function isValidTransition(from, to) {
    const allowed = VALID_TRANSITIONS[from];
    if (!allowed)
        return false;
    return allowed.includes(to);
}
// ============================================================
// Domain CRUD
// ============================================================
export function createDomain(params) {
    const now = new Date().toISOString();
    const domain = {
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
export function getDomain(id) {
    const d = store.findDomainById(id);
    return d ? d : undefined;
}
export function getDomainByDomain(domain) {
    const d = store.findDomainByDomain(domain.toLowerCase());
    return d ? d : undefined;
}
export function listDomains(customerId) {
    return store.listDomains(customerId);
}
export function updateDomainState(id, newState, failureReason) {
    const domain = store.findDomainById(id);
    if (!domain)
        return undefined;
    if (!isValidTransition(domain.state, newState)) {
        throw new Error(`Invalid state transition: ${domain.state} → ${newState}`);
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
    store.updateDomain(domain);
    return domain;
}
export function updateDomain(id, updates) {
    const domain = store.findDomainById(id);
    if (!domain)
        return undefined;
    Object.assign(domain, updates, { updatedAt: new Date().toISOString() });
    store.updateDomain(domain);
    return domain;
}
export function deleteDomain(id) {
    return store.deleteDomain(id);
}
// ============================================================
// Audit Logging
// ============================================================
export function logAudit(event) {
    const audit = {
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
export function getAuditLogs(domainId, limit = 50) {
    return store.listAuditEvents(domainId, limit);
}
// ============================================================
// ACME Order
// ============================================================
export function createAcmeOrder(params) {
    const order = {
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
export function updateAcmeOrder(id, updates) {
    const result = store.updateAcmeOrder(id, updates);
    return result ? result : undefined;
}
export function getAcmeOrder(domainId) {
    const result = store.findAcmeOrderByDomainId(domainId);
    return result ? result : undefined;
}
// ============================================================
// DNS Verification
// ============================================================
export function createDnsVerification(params) {
    const verification = {
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
export function getDnsVerifications(domainId, limit = 20) {
    return store.listDnsVerifications(domainId, limit);
}
// ============================================================
// Certificate Renewal
// ============================================================
export function createCertificateRenewal(domainId, nextRenewalAt) {
    const renewal = {
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
export function updateCertificateRenewal(id, updates) {
    const result = store.updateCertificateRenewal(id, updates);
    return result ? result : undefined;
}
export function getCertificateRenewal(domainId) {
    const result = store.findCertificateRenewalByDomainId(domainId);
    return result ? result : undefined;
}
// ============================================================
// Utility
// ============================================================
export function getDomainStats() {
    const domains = store.listDomains();
    const byState = {};
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
//# sourceMappingURL=domain-store.js.map