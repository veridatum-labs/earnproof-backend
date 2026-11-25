import { Injectable, Logger, ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import * as dns from 'dns/promises';
import * as net from 'net';
import { ProxyAgent, fetch as undiciFetch, Response } from 'undici';
import { WebhookEgressConfig } from '../../config/webhook-egress.config';

const BLOCKED_IPV4_PREFIXES = [
  /^0\./,
  /^10\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // CGNAT
  /^127\./,
  /^169\.254\./,                              // Link-local / cloud metadata
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^192\.168\./,
];

@Injectable()
export class WebhookEgressPolicyService {
  private readonly logger = new Logger(WebhookEgressPolicyService.name);
  private readonly proxyAgent: ProxyAgent | null;

  constructor(private readonly config: WebhookEgressConfig) {
    // Explicit ProxyAgent ignores NO_PROXY env bypasses
    this.proxyAgent = config.proxyUrl ? new ProxyAgent({ uri: config.proxyUrl }) : null;
  }

  private isPrivateOrBlockedIp(ip: string): boolean {
    if (net.isIPv4(ip)) {
      return BLOCKED_IPV4_PREFIXES.some((re) => re.test(ip));
    }
    if (net.isIPv6(ip)) {
      const normalized = ip.toLowerCase();
      return (
        normalized === '::1' ||
        normalized === '::' ||
        normalized.startsWith('fc') ||
        normalized.startsWith('fd') ||
        normalized.startsWith('fe80:') ||
        normalized.startsWith('::ffff:127.') ||
        normalized.startsWith('::ffff:10.') ||
        normalized.startsWith('::ffff:169.254.') ||
        normalized.startsWith('::ffff:192.168.')
      );
    }
    return true;
  }

  async assertSafeDestination(rawUrl: string): Promise<URL> {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new ForbiddenException('Invalid webhook destination URL');
    }

    if (parsed.protocol !== 'https:') {
      throw new ForbiddenException('Webhook destination must use HTTPS');
    }
    if (parsed.username || parsed.password) {
      throw new ForbiddenException('Webhook destination URL must not embed credentials');
    }

    const host = parsed.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
      throw new ForbiddenException('Blocked internal webhook destination');
    }

    if (net.isIP(host)) {
      if (this.isPrivateOrBlockedIp(host)) {
        throw new ForbiddenException('Blocked private IP webhook destination');
      }
      return parsed;
    }

    const records = await dns.lookup(host, { all: true, verbatim: true });
    if (!records.length || records.some((r) => this.isPrivateOrBlockedIp(r.address))) {
      throw new ForbiddenException('Webhook destination resolves to a blocked IP range');
    }

    return parsed;
  }

  async dispatch(url: string, init: { method: string; headers: Record<string, string>; body: string }): Promise<Response> {
    let currentUrl = (await this.assertSafeDestination(url)).toString();
    let hops = 0;

    if (this.config.mode === 'proxy_only' && !this.proxyAgent) {
      // Fail-closed: never fall back to direct sockets
      throw new ServiceUnavailableException('Egress proxy required but not configured');
    }

    while (true) {
      const startedAt = Date.now();
      let response: Response;
      try {
        response = await undiciFetch(currentUrl, {
          method: init.method,
          headers: init.headers,
          body: init.body,
          redirect: 'manual', // Never auto-follow without re-validating SSRF + proxy policy
          signal: AbortSignal.timeout(this.config.timeoutMs),
          ...(this.config.mode === 'proxy_only' ? { dispatcher: this.proxyAgent! } : {}),
        });
      } catch (err) {
        this.logger.warn({
          event: 'webhook_egress_failed',
          egressMode: this.config.mode,
          proxyHost: this.config.proxyDisplayHost, // Redacted, never contains credentials
          targetHost: new URL(currentUrl).hostname,
          latencyMs: Date.now() - startedAt,
          reason: err instanceof Error ? err.name : 'unknown_error',
        });
        throw new ServiceUnavailableException('Webhook egress delivery failed');
      }

      this.logger.log({
        event: 'webhook_egress_completed',
        egressMode: this.config.mode,
        proxyHost: this.config.proxyDisplayHost,
        targetHost: new URL(currentUrl).hostname,
        statusCode: response.status,
        latencyMs: Date.now() - startedAt,
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!this.config.allowRedirects || !location || hops >= this.config.maxRedirects) {
          throw new ForbiddenException('Webhook egress redirect blocked by policy');
        }
        hops += 1;
        // Re-validate redirect target against SSRF policy before next hop
        currentUrl = (await this.assertSafeDestination(new URL(location, currentUrl).toString())).toString();
        continue;
      }

      return response;
    }
  }
}