import { z } from "zod";

const optionalString = (schema: z.ZodString) =>
  z.preprocess(
    (value) => (value === "" ? undefined : value),
    schema.optional(),
  );

const encryptionKey = z.string().refine((value) => {
  const key = /^[a-fA-F0-9]{64}$/.test(value)
    ? Buffer.from(value, "hex")
    : Buffer.from(value, "base64");
  return key.length === 32;
}, "PAYMENT_ENCRYPTION_KEY must be 32 bytes encoded as base64 or hex");

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  APP_URL: z.string().url().default("http://localhost:3000"),
  API_URL: z.string().url().default("http://localhost:4000"),
  STELLAR_NETWORK: z.literal("testnet").default("testnet"),
  STELLAR_HORIZON_URL: z.string().url(),
  STELLAR_NETWORK_PASSPHRASE: z.string().min(1),
  SESSION_SECRET: z.string().min(8),
  CREDENTIAL_SIGNING_SECRET: z.string().min(8),
  PAYMENT_ENCRYPTION_KEY: encryptionKey,
  PAYMENT_ENCRYPTION_KEY_VERSION: z.coerce
    .number()
    .int()
    .nonnegative()
    .optional()
    .default(0),
  CONTRACT_ANCHORING_ENABLED: z
    .enum(["true", "false"])
    .optional()
    .default("false"),
  CONTRACT_ANCHORING_REQUIRED: z
    .enum(["true", "false"])
    .optional()
    .default("false"),
  STELLAR_CLI_PATH: optionalString(z.string().min(1)),
  STELLAR_CLI_SOURCE: optionalString(z.string().min(1)),
  PROOF_REGISTRY_CONTRACT_ID: optionalString(
    z.string().regex(/^C[A-Z2-7]{55}$/),
  ),
  ISSUER_REGISTRY_ENABLED: z
    .enum(["true", "false"])
    .optional()
    .default("false"),
  ISSUER_REGISTRY_CONTRACT_ID: optionalString(
    z.string().regex(/^C[A-Z2-7]{55}$/),
  ),
  EARNPROOF_ISSUER_ADDRESS: optionalString(z.string().regex(/^G[A-Z2-7]{55}$/)),
  EARNPROOF_SCHEMA_VERSION: z.coerce.number().int().positive().optional(),
  VERIFICATION_EVENT_RETENTION_DAYS: z.coerce
    .number()
    .int()
    .positive()
    .optional()
    .default(90),
  VERIFICATION_HASH_SALT_VERSION: z.coerce
    .number()
    .int()
    .nonnegative()
    .optional()
    .default(0),
});

export function validateEnv(config: Record<string, unknown>) {
  const parsed = envSchema.safeParse(config);

  if (!parsed.success) {
    throw new Error(`Invalid environment: ${parsed.error.message}`);
  }

  return parsed.data;
}
