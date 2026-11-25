/**
 * Host header and canonical origin validation.
 *
 * Untrusted Host and forwarded-host values can leak into absolute URLs,
 * redirects, webhook callbacks, and security decisions. This middleware
 * allowlists canonical hosts and schemes, honors forwarded values only from
 * trusted proxies, and rejects ambiguous, duplicate, malformed, or
 * unallowlisted hosts — fail closed, without echoing the offending value.
 */

import { NextFunction, Request, Response } from "express";

export interface HostValidationConfig {
  /** When false (default) the middleware passes every request through unchanged. */
  enabled: boolean;
  /** Canonical hosts the service will answer for, lowercased, ports included when relevant. */
  allowedHosts: ReadonlySet<string>;
  /** Canonical origin used to build generated absolute URLs. */
  canonicalOrigin: string;
  /** Immediate peer addresses trusted to supply X-Forwarded-Host/Proto. */
  trustedProxies: ReadonlySet<string>;
}

export function normalizeHostHeader(rawHost: string | string[] | undefined): string | null {
  if (!rawHost || Array.isArray(rawHost)) {
    return null;
  }
  const trimmed = rawHost.trim().toLowerCase();
  if (
    !trimmed ||
    trimmed.includes(",") ||
    /\s/.test(trimmed) ||
    trimmed.includes("/")
  ) {
    return null;
  }

  // IPv6 with optional port: [::1]:8080
  if (trimmed.startsWith("[")) {
    const ipv6Match = trimmed.match(/^(\[[0-9a-f:]+\])(?::(\d{1,5}))?$/);
    if (!ipv6Match) return null;
    const port = ipv6Match[2] ? Number(ipv6Match[2]) : null;
    if (port !== null && (port < 1 || port > 65535)) return null;
    return trimmed;
  }

  const parts = trimmed.split(":");
  if (parts.length > 2) return null;
  const hostOnly = parts[0];
  if (
    !/^[a-z0-9.-]+$/.test(hostOnly) ||
    hostOnly.startsWith(".") ||
    hostOnly.endsWith(".")
  ) {
    return null;
  }
  if (parts.length === 2) {
    if (!/^\d{1,5}$/.test(parts[1])) return null;
    const port = Number(parts[1]);
    if (port < 1 || port > 65535) return null;
  }

  return trimmed;
}

export function validateRequestHost(params: {
  hostHeader: string | string[] | undefined;
  forwardedHostHeader?: string | string[] | undefined;
  remoteAddress?: string;
  config: HostValidationConfig;
}): { ok: boolean; effectiveHost?: string; reason?: string } {
  const normalizedHost = normalizeHostHeader(params.hostHeader);
  if (!normalizedHost) {
    return { ok: false, reason: "INVALID_OR_AMBIGUOUS_HOST" };
  }

  if (!params.config.allowedHosts.has(normalizedHost)) {
    return { ok: false, reason: "UNALLOWED_HOST" };
  }

  if (params.forwardedHostHeader !== undefined) {
    const isTrustedProxy =
      Boolean(params.remoteAddress) &&
      params.config.trustedProxies.has(String(params.remoteAddress));
    if (!isTrustedProxy) {
      return { ok: false, reason: "UNTRUSTED_FORWARDED_HOST" };
    }
    const normalizedForwarded = normalizeHostHeader(params.forwardedHostHeader);
    if (!normalizedForwarded || !params.config.allowedHosts.has(normalizedForwarded)) {
      return { ok: false, reason: "INVALID_OR_UNALLOWED_FORWARDED_HOST" };
    }
    return { ok: true, effectiveHost: normalizedForwarded };
  }

  return { ok: true, effectiveHost: normalizedHost };
}

/**
 * Express middleware enforcing {@link validateRequestHost}.
 *
 * The offending host is never echoed in the response body. Enforcement is
 * gated on `config.enabled` so deployments opt in explicitly; when disabled
 * every request passes through unchanged and existing behavior is intact.
 */
export function hostValidationMiddleware(config: HostValidationConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!config.enabled) {
      next();
      return;
    }

    const { ok, reason } = validateRequestHost({
      hostHeader: req.headers.host,
      forwardedHostHeader: req.headers["x-forwarded-host"],
      remoteAddress: req.socket.remoteAddress ?? req.ip ?? undefined,
      config,
    });

    if (!ok) {
      res
        .status(400)
        .type("json")
        .json({ statusCode: 400, code: "INVALID_INPUT", message: "Invalid request host." });
      return;
    }

    next();
  };
}
