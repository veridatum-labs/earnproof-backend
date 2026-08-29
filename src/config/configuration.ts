/**
 * Collects PAYMENT_ENCRYPTION_KEY_V0, _V1, ... into an indexed object
 * (`{ 0: "...", 1: "..." }`) for the payment-encryption keyring service.
 * Loads until the first gap, same convention as VERIFICATION_HASH_SALT_V*.
 */
function loadPaymentEncryptionKeyVersions(): Record<number, string> {
  const versions: Record<number, string> = {};
  for (let i = 0; i < 100; i++) {
    const value = process.env[`PAYMENT_ENCRYPTION_KEY_V${i}`];
    if (value) {
      versions[i] = value;
    } else {
      break;
    }
  }
  return versions;
}

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
  paymentEncryptionKeyVersions: loadPaymentEncryptionKeyVersions(),
  paymentEncryptionKeyVersion: Number(
    process.env.PAYMENT_ENCRYPTION_KEY_VERSION ?? 0,
  ),
  verificationEventRetentionDays: Number(
    process.env.VERIFICATION_EVENT_RETENTION_DAYS ?? 90,
  ),
  verificationHashSaltVersion: Number(
    process.env.VERIFICATION_HASH_SALT_VERSION ?? 0,
  ),
  auth: {
    challengeRetentionDays: Number(
      process.env.AUTH_CHALLENGE_RETENTION_DAYS ?? 7,
    ),
    auditRetentionDays: Number(process.env.AUTH_AUDIT_RETENTION_DAYS ?? 90),
    rateLimits: {
      maxChallengeCreations: Number(
        process.env.AUTH_RATE_LIMIT_MAX_CHALLENGE_CREATIONS ?? 10,
      ),
      challengeCreationWindowMs: Number(
        process.env.AUTH_RATE_LIMIT_CHALLENGE_CREATION_WINDOW_MS ?? 900000, // 15 minutes
      ),
      maxVerifications: Number(
        process.env.AUTH_RATE_LIMIT_MAX_VERIFICATIONS ?? 5,
      ),
      verificationWindowMs: Number(
        process.env.AUTH_RATE_LIMIT_VERIFICATION_WINDOW_MS ?? 900000, // 15 minutes
      ),
    },
  },
  contractAnchoring: {
    enabled: process.env.CONTRACT_ANCHORING_ENABLED === "true",
    required: process.env.CONTRACT_ANCHORING_REQUIRED === "true",
    stellarCliPath: process.env.STELLAR_CLI_PATH ?? "stellar",
    source: process.env.STELLAR_CLI_SOURCE,
    proofRegistryContractId: process.env.PROOF_REGISTRY_CONTRACT_ID,
    issuerAddress: process.env.EARNPROOF_ISSUER_ADDRESS,
    schemaVersion: Number(process.env.EARNPROOF_SCHEMA_VERSION ?? 1),
  },
  health: {
    // Probe timeout. Must stay below the orchestrator's own probe timeout, or a
    // slow dependency produces overlapping in-flight probes against a system
    // that is already struggling.
    probeTimeoutMs: Number(process.env.HEALTH_PROBE_TIMEOUT_MS ?? 2000),
    // How long a probe result is reused. Readiness is polled continuously by
    // every replica and load balancer, so without caching the probe load scales
    // with poll rate rather than with anything meaningful.
    cacheTtlMs: Number(process.env.HEALTH_CACHE_TTL_MS ?? 5000),
  },
  issuerRegistry: {
    enabled: process.env.ISSUER_REGISTRY_ENABLED === "true",
    stellarCliPath: process.env.STELLAR_CLI_PATH ?? "stellar",
    source: process.env.STELLAR_CLI_SOURCE,
    contractId: process.env.ISSUER_REGISTRY_CONTRACT_ID,
  },
});
