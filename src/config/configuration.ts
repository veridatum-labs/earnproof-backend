export const configuration = () => ({
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: Number(process.env.PORT ?? 4000),
  databaseUrl: process.env.DATABASE_URL,
  redisUrl: process.env.REDIS_URL,
  appUrl: process.env.APP_URL ?? "http://localhost:3000",
  apiUrl: process.env.API_URL ?? "http://localhost:4000",
  stellar: {
    network: process.env.STELLAR_NETWORK ?? "testnet",
    horizonUrl:
      process.env.STELLAR_HORIZON_URL ?? "https://horizon-testnet.stellar.org",
    networkPassphrase:
      process.env.STELLAR_NETWORK_PASSPHRASE ??
      "Test SDF Network ; September 2015",
  },
  sessionSecret: process.env.SESSION_SECRET,
  credentialSigningSecret: process.env.CREDENTIAL_SIGNING_SECRET,
  paymentEncryptionKey: process.env.PAYMENT_ENCRYPTION_KEY,
  contractAnchoring: {
    enabled: process.env.CONTRACT_ANCHORING_ENABLED === "true",
    required: process.env.CONTRACT_ANCHORING_REQUIRED === "true",
    stellarCliPath: process.env.STELLAR_CLI_PATH ?? "stellar",
    source: process.env.STELLAR_CLI_SOURCE,
    proofRegistryContractId: process.env.PROOF_REGISTRY_CONTRACT_ID,
    issuerAddress: process.env.EARNPROOF_ISSUER_ADDRESS,
    schemaVersion: Number(process.env.EARNPROOF_SCHEMA_VERSION ?? 1),
  },
  rateLimit: {
    // "default": the global ceiling applied to every route that doesn't opt
    // into a stricter named throttler below. Anonymous callers get this
    // limit; RoleAwareThrottlerGuard multiplies it for authenticated ones
    // (see rateLimitAuthenticatedMultiplier).
    defaultTtlMs: Number(process.env.RATE_LIMIT_DEFAULT_TTL_MS ?? 60_000),
    defaultLimit: Number(process.env.RATE_LIMIT_DEFAULT_LIMIT ?? 100),
    // "strict": expensive operations — proof creation, payment sync.
    strictTtlMs: Number(process.env.RATE_LIMIT_STRICT_TTL_MS ?? 60_000),
    strictLimit: Number(process.env.RATE_LIMIT_STRICT_LIMIT ?? 10),
    // "verification": the public, unauthenticated proof-verification lookup
    // — needs its own (generous but bounded) budget since it's the one
    // sensitive endpoint anonymous callers hit routinely, not just abusively.
    verificationTtlMs: Number(process.env.RATE_LIMIT_VERIFICATION_TTL_MS ?? 60_000),
    verificationLimit: Number(process.env.RATE_LIMIT_VERIFICATION_LIMIT ?? 30),
    // How much more an authenticated caller gets over an anonymous one, on
    // every named throttler uniformly (a flat multiplier, not a separate
    // config value per tier, so the tiers stay comparable to each other).
    authenticatedMultiplier: Number(
      process.env.RATE_LIMIT_AUTHENTICATED_MULTIPLIER ?? 3,
    ),
  },
});
