/**
 * SSRF protection for outbound webhook deliveries.
 *
 * This module is the webhook-facing entry point. All destination-validation
 * policy — scheme/port allowlisting, credential rejection, IP-range
 * blocking, DNS-revalidation-at-connect-time — is centralised in
 * `../common/http/destination-guard`; this file only re-exports it under the
 * names the webhook call sites already use, plus a webhook-flavoured error
 * type so existing `instanceof` checks keep working.
 *
 * See `../common/http/destination-guard.ts` for the full policy and its
 * rationale.
 */

import { lookup } from "node:dns/promises";
import {
  DestinationBlockedError,
  assertSafeDestination,
  assertSafeDestinationUrl,
} from "../common/http/destination-guard";

export class SsrfBlockedError extends DestinationBlockedError {
  constructor(reason: string) {
    super(reason);
    this.name = "SsrfBlockedError";
    // Keep the historical "SSRF" wording in the message — call sites and
    // stored failure reasons match against it — while `reason` (inherited)
    // still carries the plain, prefix-free explanation.
    this.message = `SSRF: blocked destination — ${reason}`;
  }
}

function rethrowAsSsrfError(err: unknown): never {
  if (err instanceof DestinationBlockedError) {
    throw new SsrfBlockedError(err.reason);
  }
  throw err;
}

/**
 * Throw `SsrfBlockedError` if `url` targets a forbidden destination on the
 * URL/scheme/credential/host level. Does not perform DNS resolution — call
 * `assertSafeWebhookDestination` for that immediately before delivering.
 */
export function assertSafeWebhookUrl(raw: string): void {
  try {
    assertSafeDestinationUrl(raw);
  } catch (err) {
    rethrowAsSsrfError(err);
  }
}

/**
 * Resolve a hostname immediately before delivery and reject it when any
 * returned address is non-public. Re-run this right before every delivery
 * attempt and retry — not just once at enqueue time — so a hostname's
 * resolved address is only ever trusted for the instant this function
 * checked it (defeats DNS-rebinding / TOCTOU).
 */
export async function assertSafeWebhookDestination(
  raw: string,
  resolve: typeof lookup = lookup,
): Promise<void> {
  try {
    await assertSafeDestination(raw, resolve);
  } catch (err) {
    rethrowAsSsrfError(err);
  assertSafeWebhookUrl(raw);
  const parsed = new URL(raw);
  const host = parsed.hostname.replace(/^\[|\]$/g, "");

  if (parseIPv4(host) !== null || parseIPv6(host) !== null) return;

  const addresses = await resolve(host, { all: true, verbatim: true });
  if (addresses.length === 0) {
    throw new SsrfBlockedError(`destination ${host} did not resolve`);
  }
  for (const { address } of addresses) {
    if (isBlockedHost(address)) {
      throw new SsrfBlockedError(
        `destination ${host} resolved to a non-public address`,
      );
    }
  }
}

function isBlockedHost(host: string): boolean {
  // Check if it parses as a numeric IP address
  const v4 = parseIPv4(host);
  if (v4 !== null) {
    return isBlockedIPv4(v4);
  }

  const v6 = parseIPv6(host);
  if (v6 !== null) {
    return isBlockedIPv6(v6);
  }

  // Hostnames: block "localhost" and any *.local / *.internal / *.localhost
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  return false;
}

/**
 * Parse a dotted-decimal IPv4 string into a 32-bit unsigned integer,
 * or return null if not a valid IPv4 address.
 */
function parseIPv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(Number);
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return null;
  }
  return ((octets[0]! << 24) | (octets[1]! << 16) | (octets[2]! << 8) | octets[3]!) >>> 0;
}

function isBlockedIPv4(ip: number): boolean {
  // 0.0.0.0/8
  if ((ip >>> 24) === 0) return true;
  // 10.0.0.0/8
  if ((ip >>> 24) === 10) return true;
  // 100.64.0.0/10 (CGN / shared address space)
  if ((ip >>> 22) === (0x64400000 >>> 22)) return true;
  // 127.0.0.0/8 — loopback
  if ((ip >>> 24) === 127) return true;
  // 169.254.0.0/16 — link-local & cloud metadata (AWS, Azure, GCP)
  if ((ip >>> 16) === 0xa9fe) return true;
  // 172.16.0.0/12 — private
  if ((ip >>> 20) === (0xac100000 >>> 20)) return true;
  // 192.168.0.0/16 — private
  if ((ip >>> 16) === 0xc0a8) return true;
  // 198.18.0.0/15 — benchmark / testing
  if ((ip >>> 17) === (0xc6120000 >>> 17)) return true;
  // 198.51.100.0/24 — TEST-NET-2
  if ((ip >>> 8) === 0xc6336400 >>> 8) return true;
  // 203.0.113.0/24 — TEST-NET-3
  if ((ip >>> 8) === 0xcb007100 >>> 8) return true;
  // 240.0.0.0/4 — reserved
  if ((ip >>> 28) === 0xf) return true;
  // 255.255.255.255
  if (ip === 0xffffffff) return true;
  // Alibaba Cloud metadata 100.100.100.200
  if (ip === parseIPv4("100.100.100.200")) return true;

  return false;
}

/**
 * Very lightweight IPv6 parse: just checks a handful of blocked prefixes
 * without a full 128-bit parse.  Handles common representations.
 */
function parseIPv6(host: string): string | null {
  // IPv6 addresses contain at least one colon
  if (!host.includes(":")) return null;
  return host;
}

function isBlockedIPv6(addr: string): boolean {
  // Loopback ::1
  if (addr === "::1" || addr === "0:0:0:0:0:0:0:1") return true;
  // Unspecified ::
  if (addr === "::" || addr === "0:0:0:0:0:0:0:0") return true;
  // Link-local fe80::/10
  const lower = addr.toLowerCase();
  if (lower.startsWith("fe8") || lower.startsWith("fe9") ||
      lower.startsWith("fea") || lower.startsWith("feb")) return true;
  // Unique local fc00::/7
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  // IPv4-mapped ::ffff:a.b.c.d or ::ffff:0a..
  if (lower.startsWith("::ffff:")) {
    const mapped = lower.slice("::ffff:".length);
    // Could be dotted-decimal or hex
    const v4Dotted = parseIPv4(mapped);
    if (v4Dotted !== null && isBlockedIPv4(v4Dotted)) return true;
  }
}
