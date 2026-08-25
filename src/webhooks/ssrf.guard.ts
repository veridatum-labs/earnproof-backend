/**
 * SSRF protection for outbound webhook deliveries.
 *
 * Rules enforced before any HTTP request is made:
 *  1. URL must use the `https:` scheme (plain `http:` is rejected).
 *  2. Hostname must not resolve to a private, link-local, loopback,
 *     cloud-metadata, or otherwise unsafe IP address.
 *  3. Redirects are NOT followed — any 3xx response from the target is
 *     treated as a permanent failure.  This prevents open-redirect attacks
 *     that would carry the signed payload to an internal address.
 *
 * Blocked IP ranges (IPv4):
 *   10.0.0.0/8         Private (Class A)
 *   172.16.0.0/12      Private (Class B)
 *   192.168.0.0/16     Private (Class C)
 *   127.0.0.0/8        Loopback
 *   169.254.0.0/16     Link-local / cloud-metadata (AWS, Azure, GCP IMDSv1/v2
 *                      and Alibaba Cloud all use 169.254.169.254)
 *   100.64.0.0/10      Carrier-grade NAT / shared address space
 *   0.0.0.0/8          "This" network
 *   198.18.0.0/15      Network benchmark tests
 *   192.0.2.0/24       TEST-NET-1 (documentation)
 *   198.51.100.0/24    TEST-NET-2
 *   203.0.113.0/24     TEST-NET-3
 *   240.0.0.0/4        Reserved / future use
 *
 * Blocked IP ranges (IPv6):
 *   ::1/128            Loopback
 *   fc00::/7           Unique-local (ULA)
 *   fe80::/10          Link-local
 *   ::ffff:0:0/96      IPv4-mapped (re-checked against IPv4 blocklist)
 *
 * In test environments (`NODE_ENV=test`) HTTPS enforcement is relaxed to
 * allow `http://localhost` as a target so unit tests can use local mock
 * servers without TLS.
 */
import { BadRequestException } from "@nestjs/common";
import * as dns from "dns";

// ---------------------------------------------------------------------------
// IPv4 range blocking
// ---------------------------------------------------------------------------

type IPv4Range = { base: number; mask: number };

function parseIPv4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = (result << 8) | num;
  }
  // Treat as unsigned 32-bit
  return result >>> 0;
}

function buildRange(cidr: string): IPv4Range {
  const [base, bits] = cidr.split("/");
  const mask = bits ? ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0 : 0xffffffff;
  return { base: (parseIPv4(base) ?? 0) >>> 0, mask };
}

const BLOCKED_IPV4_RANGES: IPv4Range[] = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "100.64.0.0/10",
  "0.0.0.0/8",
  "198.18.0.0/15",
  "192.0.2.0/24",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "240.0.0.0/4",
].map(buildRange);

function isBlockedIPv4(ip: string): boolean {
  const num = parseIPv4(ip);
  if (num === null) return false;
  return BLOCKED_IPV4_RANGES.some(
    (range) => (num & range.mask) >>> 0 === range.base,
  );
}

// ---------------------------------------------------------------------------
// IPv6 range blocking
// ---------------------------------------------------------------------------

function parseIPv6(ip: string): Buffer | null {
  // Remove zone index
  const clean = ip.split("%")[0];

  // Handle :: expansion
  const halves = clean.split("::");
  if (halves.length > 2) return null;

  const expandGroup = (s: string) => (s === "" ? [] : s.split(":"));
  const left = expandGroup(halves[0]);
  const right = halves.length === 2 ? expandGroup(halves[1]) : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;

  const groups = [
    ...left,
    ...Array<string>(missing).fill("0"),
    ...right,
  ];
  if (groups.length !== 8) return null;

  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    if (isNaN(val) || val < 0 || val > 0xffff) return null;
    buf.writeUInt16BE(val, i * 2);
  }
  return buf;
}

function isBlockedIPv6(ip: string): boolean {
  const buf = parseIPv6(ip);
  if (!buf) return false;

  // ::1 loopback
  if (buf.equals(Buffer.from("00000000000000000000000000000001", "hex"))) {
    return true;
  }

  // fc00::/7 — unique-local (ULA): first byte & 0xfe === 0xfc
  if ((buf[0] & 0xfe) === 0xfc) return true;

  // fe80::/10 — link-local: first byte 0xfe, second byte & 0xc0 === 0x80
  if (buf[0] === 0xfe && (buf[1] & 0xc0) === 0x80) return true;

  // ::ffff:0:0/96 — IPv4-mapped: bytes 0-9 = 0, bytes 10-11 = 0xff
  if (
    buf.slice(0, 10).equals(Buffer.alloc(10)) &&
    buf[10] === 0xff &&
    buf[11] === 0xff
  ) {
    const ipv4 = `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
    return isBlockedIPv4(ipv4);
  }

  return false;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export class SsrfGuard {
  /**
   * Validate that a webhook target URL is safe to deliver to.
   *
   * Performs:
   *   - Scheme check (https only, relaxed in test env)
   *   - Hostname extraction and basic sanity
   *   - DNS resolution of the hostname
   *   - IP range check on every resolved address
   *
   * @throws BadRequestException with a safe (non-leaking) message on failure.
   */
  static async assertSafeUrl(
    rawUrl: string,
    opts: { allowHttp?: boolean } = {},
  ): Promise<void> {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new BadRequestException("Webhook URL is not a valid URL");
    }

    const isTest = process.env.NODE_ENV === "test";
    const allowHttp = opts.allowHttp === true || isTest;

    if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) {
      throw new BadRequestException(
        "Webhook URL must use HTTPS",
      );
    }

    const hostname = parsed.hostname;
    if (!hostname) {
      throw new BadRequestException("Webhook URL has no hostname");
    }

    // Reject bare IP literals that are blocked directly
    if (isBlockedIPv4(hostname)) {
      throw new BadRequestException("Webhook URL resolves to a blocked address");
    }
    if (isBlockedIPv6(hostname.replace(/^\[|\]$/g, ""))) {
      throw new BadRequestException("Webhook URL resolves to a blocked address");
    }

    // Resolve hostname via DNS and check every returned address
    const addresses = await SsrfGuard.resolveHostname(hostname);

    if (addresses.length === 0) {
      throw new BadRequestException("Webhook URL hostname does not resolve");
    }

    for (const addr of addresses) {
      if (isBlockedIPv4(addr) || isBlockedIPv6(addr)) {
        throw new BadRequestException(
          "Webhook URL resolves to a blocked address",
        );
      }
    }
  }

  /** Resolve a hostname to all IPv4 and IPv6 addresses it maps to. */
  private static async resolveHostname(hostname: string): Promise<string[]> {
    const results: string[] = [];

    await Promise.allSettled([
      dns.promises.resolve4(hostname).then((addrs) => results.push(...addrs)),
      dns.promises.resolve6(hostname).then((addrs) => results.push(...addrs)),
    ]);

    return results;
  }
}
