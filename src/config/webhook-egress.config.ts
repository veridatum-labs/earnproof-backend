export type WebhookEgressMode = 'direct' | 'proxy_only';

export interface WebhookEgressConfig {
  mode: WebhookEgressMode;
  proxyUrl: string | null;
  proxyDisplayHost: string | null; // Safe for logs/metrics (no userinfo)
  allowRedirects: boolean;
  maxRedirects: number;
  timeoutMs: number;
}

export function loadWebhookEgressConfig(env: NodeJS.ProcessEnv = process.env): WebhookEgressConfig {
  const rawMode = (env.WEBHOOK_EGRESS_MODE ?? 'direct').trim().toLowerCase();
  if (rawMode !== 'direct' && rawMode !== 'proxy_only') {
    throw new Error(`Invalid WEBHOOK_EGRESS_MODE: ${rawMode}`);
  }

  const rawProxyUrl = env.WEBHOOK_EGRESS_PROXY_URL?.trim() || null;

  if (rawMode === 'proxy_only' && !rawProxyUrl) {
    throw new Error('WEBHOOK_EGRESS_PROXY_URL is required when WEBHOOK_EGRESS_MODE=proxy_only');
  }

  let proxyDisplayHost: string | null = null;
  if (rawProxyUrl) {
    const parsed = new URL(rawProxyUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error(`Unsupported proxy protocol: ${parsed.protocol}`);
    }
    // Strip username/password permanently for observability
    proxyDisplayHost = `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ''}`;
  }

  return {
    mode: rawMode,
    proxyUrl: rawProxyUrl,
    proxyDisplayHost,
    allowRedirects: env.WEBHOOK_EGRESS_ALLOW_REDIRECTS === 'true',
    maxRedirects: Number(env.WEBHOOK_EGRESS_MAX_REDIRECTS ?? 0),
    timeoutMs: Number(env.WEBHOOK_EGRESS_TIMEOUT_MS ?? 10_000),
  };
}