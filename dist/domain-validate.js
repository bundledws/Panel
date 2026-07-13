import { runCmd } from "./cmd.js";
// ============================================================
// Domain Validation — Security-First
// ============================================================
const BLOCKED_TLDS = [
    ".local", ".internal", ".invalid", ".test", ".example",
    ".localhost", ".lan", ".home", ".corp", ".arpa",
    ".localdomain", ".localhost.localdomain",
];
const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
/**
 * Validate a domain string with exhaustive security checks.
 * Returns the normalized domain or throws with a descriptive error.
 */
export function validateDomain(input, managedDomain) {
    // 1. Trim and lowercase
    const domain = input.trim().toLowerCase();
    // 2. Reject empty
    if (!domain)
        throw new Error("Domain is required");
    // 3. Reject wildcards at this stage
    if (domain.startsWith("*."))
        throw new Error("Wildcard domains must be configured separately");
    // 4. Reject IP addresses (IPv4)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        throw new Error("IP addresses are not allowed as domains");
    }
    // 5. Reject IP addresses (IPv6)
    if (/^\[?[0-9a-f:]+\]?$/.test(domain) && domain.includes(":")) {
        throw new Error("IP addresses are not allowed as domains");
    }
    // 6. Reject internal/special-use TLDs
    for (const tld of BLOCKED_TLDS) {
        if (domain.endsWith(tld))
            throw new Error(`Invalid TLD: ${tld}`);
    }
    // 7. Reject localhost
    if (domain === "localhost" || domain.startsWith("localhost.")) {
        throw new Error("Localhost is not allowed");
    }
    // 8. Reject domains with invalid characters
    if (/[^a-z0-9.\-]/.test(domain)) {
        throw new Error("Domain contains invalid characters");
    }
    // 9. Reject consecutive dots
    if (domain.includes(".."))
        throw new Error("Domain contains consecutive dots");
    // 10. Reject labels starting or ending with hyphen
    for (const label of domain.split(".")) {
        if (!label)
            throw new Error("Domain contains empty labels");
        if (label.startsWith("-") || label.endsWith("-")) {
            throw new Error(`Domain label "${label}" starts or ends with a hyphen`);
        }
    }
    // 11. Length checks
    if (domain.length > 253)
        throw new Error("Domain too long (max 253 characters)");
    for (const label of domain.split(".")) {
        if (label.length > 63)
            throw new Error(`Domain label "${label}" too long (max 63 characters)`);
    }
    // 12. Strict domain regex (Punycode allowed — it's ASCII)
    if (!DOMAIN_REGEX.test(domain)) {
        throw new Error("Invalid domain format");
    }
    // 13. Reject the panel's own managed subdomain
    if (managedDomain && domain === managedDomain) {
        throw new Error("Cannot add the panel's own domain");
    }
    // 14. Reject if domain is already managed by the panel (subdomain check)
    if (managedDomain && domain.endsWith("." + managedDomain)) {
        // Allow subdomains of the managed domain? Only if not the panel's own subdomain pattern
        // The panel uses vps-{hex}.domain pattern — reject those
        if (/^vps-[a-f0-9]+\./.test(domain)) {
            throw new Error("Cannot add a panel-managed subdomain");
        }
    }
    return domain;
}
// ============================================================
// Private IP Detection
// ============================================================
/**
 * Check if an IP address is private, loopback, link-local, or otherwise
 * non-routable on the public internet.
 */
export function isPrivateIp(ip) {
    const trimmed = ip.trim();
    // IPv4 checks
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
        const parts = trimmed.split(".").map(Number);
        if (parts.some(p => p < 0 || p > 255))
            return true; // Invalid octet
        // 10.0.0.0/8
        if (parts[0] === 10)
            return true;
        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
            return true;
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168)
            return true;
        // 127.0.0.0/8 (loopback)
        if (parts[0] === 127)
            return true;
        // 0.0.0.0/8
        if (parts[0] === 0)
            return true;
        // 169.254.0.0/16 (link-local)
        if (parts[0] === 169 && parts[1] === 254)
            return true;
        // 100.64.0.0/10 (CGNAT)
        if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
            return true;
        // 198.18.0.0/15 (benchmarking)
        if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19))
            return true;
        // 240.0.0.0/4 (reserved)
        if (parts[0] >= 240)
            return true;
        return false;
    }
    // IPv6 checks
    const v6 = trimmed.replace(/^\[|\]$/g, "").toLowerCase();
    if (/^[0-9a-f:]+$/.test(v6)) {
        // ::1 (loopback)
        if (v6 === "::1" || v6 === "0:0:0:0:0:0:0:1")
            return true;
        // :: (unspecified)
        if (v6 === "::" || v6 === "0:0:0:0:0:0:0:0")
            return true;
        // fe80::/10 (link-local)
        if (v6.startsWith("fe80") || v6.startsWith("fe8") || v6.startsWith("fe9") ||
            v6.startsWith("fea") || v6.startsWith("feb"))
            return true;
        // fc00::/7 (unique local)
        if (v6.startsWith("fc") || v6.startsWith("fd"))
            return true;
        // ff00::/8 (multicast) — not private per se, but not routable for our purposes
        if (v6.startsWith("ff"))
            return true;
        return false;
    }
    // Not a recognizable IP format
    return true; // Safer to reject unknown formats
}
// ============================================================
// Cloudflare IP Detection
// ============================================================
// Cloudflare's published IPv4 ranges (as of 2024)
// Source: https://www.cloudflare.com/ips-v4
const CLOUDFLARE_IPV4_RANGES = [
    { start: "173.245.48.0", end: "173.245.63.255" },
    { start: "103.21.244.0", end: "103.21.247.255" },
    { start: "103.22.200.0", end: "103.22.203.255" },
    { start: "103.31.4.0", end: "103.31.7.255" },
    { start: "141.101.64.0", end: "141.101.127.255" },
    { start: "108.162.192.0", end: "108.162.255.255" },
    { start: "190.93.240.0", end: "190.93.255.255" },
    { start: "188.114.96.0", end: "188.114.127.255" },
    { start: "197.234.240.0", end: "197.234.255.255" },
    { start: "198.41.128.0", end: "198.41.255.255" },
    { start: "162.158.0.0", end: "162.159.255.255" },
    { start: "104.16.0.0", end: "104.31.255.255" },
    { start: "172.64.0.0", end: "172.71.255.255" },
    { start: "131.0.72.0", end: "131.0.75.255" },
];
// Cloudflare's published IPv6 ranges (as of 2024)
// Source: https://www.cloudflare.com/ips-v6
const CLOUDFLARE_IPV6_PREFIXES = [
    "2400:cb00::",
    "2606:4700::",
    "2803:f800::",
    "2405:b500::",
    "2405:8100::",
    "2a06:98c0::",
    "2c0f:f350::",
];
function ipToNumber(ip) {
    const parts = ip.split(".").map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
function isIpInRange(ip, start, end) {
    const ipNum = ipToNumber(ip);
    const startNum = ipToNumber(start);
    const endNum = ipToNumber(end);
    return ipNum >= startNum && ipNum <= endNum;
}
/**
 * Check if an IP address belongs to Cloudflare's proxy network.
 */
export function isCloudflareIp(ip) {
    const trimmed = ip.trim();
    // IPv4 check
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
        for (const range of CLOUDFLARE_IPV4_RANGES) {
            if (isIpInRange(trimmed, range.start, range.end))
                return true;
        }
        return false;
    }
    // IPv6 check
    const v6 = trimmed.replace(/^\[|\]$/g, "").toLowerCase();
    for (const prefix of CLOUDFLARE_IPV6_PREFIXES) {
        const normalizedPrefix = prefix.toLowerCase().replace(/::$/, "");
        if (v6.startsWith(normalizedPrefix))
            return true;
    }
    return false;
}
export async function detectProxyStatus(domain) {
    try {
        const ips = await resolveDomain(domain);
        if (ips.length === 0)
            return "unknown";
        // Check if ALL resolved IPs are Cloudflare IPs
        const allCloudflare = ips.every(ip => isCloudflareIp(ip));
        if (allCloudflare)
            return "proxied";
        // Check if ANY resolved IP is a Cloudflare IP (mixed mode)
        const anyCloudflare = ips.some(ip => isCloudflareIp(ip));
        if (anyCloudflare)
            return "proxied"; // Treat mixed as proxied
        return "dns-only";
    }
    catch {
        return "unknown";
    }
}
const DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
/**
 * Resolve a domain using multiple trusted DNS resolvers.
 * Returns all unique IPs found across resolvers.
 */
export async function resolveDomain(domain) {
    const allIps = [];
    for (const resolver of DNS_RESOLVERS) {
        try {
            const result = await runCmd("dig", ["+short", domain, "@" + resolver], undefined, 10000);
            const ips = result.stdout
                .split("\n")
                .map(l => l.trim())
                .filter(l => l && /^\d/.test(l) && !l.startsWith(";")); // Only IP results
            allIps.push(...ips);
        }
        catch {
            // Resolver failed, try next
            continue;
        }
    }
    // Deduplicate while preserving order
    return [...new Set(allIps)];
}
/**
 * Verify that a domain's DNS resolves correctly.
 * For DNS-only: checks that the domain resolves to the expected origin IP.
 * For proxied: checks that the domain resolves to Cloudflare IPs (proxied is valid).
 * Rejects private IPs in all cases.
 */
export async function verifyDnsResolution(domain, expectedIp) {
    const resolvedIps = await resolveDomain(domain);
    // Filter out private IPs
    const publicIps = resolvedIps.filter(ip => !isPrivateIp(ip));
    // Detect proxy status
    const proxyStatus = await detectProxyStatus(domain);
    // Check if the domain is correctly configured:
    // - DNS-only: expected IP must be in the resolved set
    // - Proxied: Cloudflare IPs are expected (domain is behind CF)
    // - Mixed: treat as proxied
    let match;
    if (proxyStatus === "proxied") {
        // Domain is behind Cloudflare — that's valid configuration
        match = true;
    }
    else {
        // DNS-only — check for exact IP match
        match = publicIps.includes(expectedIp);
    }
    // Try to get TTL
    let ttl = null;
    try {
        const result = await runCmd("dig", ["+ttlid", domain, "@1.1.1.1"], undefined, 10000);
        const match = result.stdout.match(/\d+\s+IN\s+A\s+/);
        if (match) {
            ttl = parseInt(match[0].split(/\s+/)[0], 10);
        }
    }
    catch { }
    return {
        resolvedIps: publicIps,
        match,
        ttl,
        proxyStatus,
    };
}
/**
 * Poll DNS until the domain resolves correctly.
 * Accepts both DNS-only (exact IP match) and proxied (Cloudflare IPs) as valid.
 * Returns true if resolution is correct and stable (3 consecutive checks).
 * Throws on timeout or if IP resolves to private ranges.
 */
export async function pollDnsUntilVerified(domain, expectedIp, maxAttempts = 30, intervalMs = 10000) {
    let consecutiveMatches = 0;
    const requiredConsecutive = 3;
    let lastCheck = { resolvedIps: [], match: false, ttl: null, proxyStatus: "unknown" };
    for (let i = 0; i < maxAttempts; i++) {
        lastCheck = await verifyDnsResolution(domain, expectedIp);
        if (lastCheck.match) {
            consecutiveMatches++;
            if (consecutiveMatches >= requiredConsecutive) {
                return { verified: true, attempts: i + 1, lastCheck };
            }
        }
        else {
            consecutiveMatches = 0;
            // Check if resolved to private IP — that's an error
            const resolvedIps = await resolveDomain(domain);
            for (const ip of resolvedIps) {
                if (isPrivateIp(ip)) {
                    throw new Error(`Domain ${domain} resolves to private IP ${ip}. ` +
                        `Make sure the DNS A record points to your server's public IP: ${expectedIp}`);
                }
            }
        }
        // Wait before next attempt
        if (i < maxAttempts - 1) {
            await new Promise(r => setTimeout(r, intervalMs));
        }
    }
    return { verified: false, attempts: maxAttempts, lastCheck };
}
/**
 * Generate DNS instructions for the customer to configure their domain.
 * Includes Cloudflare proxy guidance.
 */
export function generateDnsInstructions(domain, publicIp) {
    const apex = domain;
    const www = `www.${domain}`;
    return {
        records: [
            {
                type: "A",
                name: "@",
                value: publicIp,
                ttl: "Auto (or 300)",
                purpose: `Points ${apex} to your server`,
            },
            {
                type: "A",
                name: "www",
                value: publicIp,
                ttl: "Auto (or 300)",
                purpose: `Points ${www} to your server`,
            },
        ],
        proxyNote: "Cloudflare proxy (orange cloud) is fully supported. You can leave it enabled — the system will automatically detect it and use DNS-based certificate validation.",
    };
}
//# sourceMappingURL=domain-validate.js.map