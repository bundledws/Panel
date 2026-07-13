# BundledWS — Secure Custom Domain Automation Implementation Plan

## Overview
Implement a production-ready, secure, automated domain management system for BundledWS that supports customer-managed DNS (Mode A) and managed DNS via Cloudflare (Mode B), with full ACME certificate automation, nginx per-domain config, and rollback safety.

## Files to Create

| # | File | Purpose |
|---|------|---------|
| 1 | `src/domain-store.ts` | Domain data model, state machine transitions, CRUD, audit logging |
| 2 | `src/domain-validate.ts` | Domain syntax validation, DNS resolution verification, IP security checks |
| 3 | `src/certificate.ts` | ACME certificate issuance (HTTP-01/DNS-01), renewal, verification, cleanup |
| 4 | `src/domain-manager.ts` | State machine orchestrator, workflow coordination, locking |

## Files to Extend

| # | File | Changes |
|---|------|---------|
| 5 | `src/nginx.ts` | Add per-domain config generation, shared snippets, nginx lock, config backup/rollback |
| 6 | `src/server.ts` | Add domain API routes (CRUD, verify, cert, retry, rollback) |
| 7 | `src/spa.html` | Replace static domain page with interactive domain management UI |
| 8 | `src/store.ts` | Add domain/certificate/audit storage collections |

## Implementation Order

### Phase 1: Data Layer
- [ ] 1a. Create `src/domain-store.ts` with all interfaces (Domain, AuditEvent, AcmeOrder, DnsVerification, CertificateRenewal)
- [ ] 1b. Implement state machine with valid transition map
- [ ] 1c. Implement CRUD operations (add, get, list, update, delete)
- [ ] 1d. Implement audit logging
- [ ] 1e. Integrate with `src/store.ts` for persistence

### Phase 2: Validation Layer
- [ ] 2a. Create `src/domain-validate.ts`
- [ ] 2b. Implement `validateDomain()` with all security checks (reject IPs, private TLDs, localhost, malformed, etc.)
- [ ] 2c. Implement `isPrivateIp()` for IPv4 and IPv6
- [ ] 2d. Implement `verifyDnsResolution()` with multi-resolver polling
- [ ] 2e. Implement DNS stability check (3 consecutive consistent resolutions)

### Phase 3: Nginx Config Generation
- [ ] 3a. Extend `src/nginx.ts` with `generatePerDomainConfig()` 
- [ ] 3b. Add `generateDefaultServerBlock()` for catch-all
- [ ] 3c. Add shared snippet files (proxy-headers.conf, ssl-defaults.conf)
- [ ] 3d. Add `writeDomainConfig()` with atomic write + backup
- [ ] 3e. Add `removeDomainConfig()` with rollback
- [ ] 3f. Add `withNginxLock()` for concurrency safety
- [ ] 3g. Add `listConfiguredDomains()` to detect duplicates

### Phase 4: Certificate Automation
- [ ] 4a. Create `src/certificate.ts`
- [ ] 4b. Implement `issueCertificateHttp01()` using acme.sh --webroot
- [ ] 4c. Implement `issueCertificateDns01()` using acme.sh --dns dns_cf
- [ ] 4d. Implement `renewCertificate()`
- [ ] 4e. Implement `verifyCertificate()` (openssl verify, expiry check)
- [ ] 4f. Implement `cleanupChallenge()`
- [ ] 4g. Implement rate-limit-aware retry with exponential backoff

### Phase 5: Domain State Machine Orchestrator
- [ ] 5a. Create `src/domain-manager.ts`
- [ ] 5b. Implement `addDomain()` — full workflow orchestrator
- [ ] 5c. Implement `removeDomain()` — cleanup nginx, cert, DNS records
- [ ] 5d. Implement `retryDomain()` — reset and retry from failed state
- [ ] 5e. Implement `rollbackDomain()` — restore previous state
- [ ] 5f. Implement `verifyHealth()` — periodic check

### Phase 6: API Routes
- [ ] 6a. Add domain API endpoints to `src/server.ts`
- [ ] 6b. Add authentication + CSRF protection for all domain routes
- [ ] 6c. Add rate limiting for domain operations
- [ ] 6d. Add input validation middleware

### Phase 7: Frontend UI
- [ ] 7a. Replace static domain page in `src/spa.html` with interactive management
- [ ] 7b. Add "Add Domain" form with mode selection
- [ ] 7c. Add domain list with status badges and controls
- [ ] 7d. Add DNS instructions display with copy IP
- [ ] 7e. Add retry/rollback/remove buttons per domain
- [ ] 7f. Add certificate details display
- [ ] 7g. Add audit log viewer

### Phase 8: Integration & Final Wiring
- [ ] 8a. Wire up renewal cron hook
- [ ] 8b. Add health check endpoint for domains
- [ ] 8c. Test all state transitions
- [ ] 8d. Test rollback scenarios
- [ ] 8e. Verify nginx config isolation