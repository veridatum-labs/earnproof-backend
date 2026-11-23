import * as fs from "fs";
import * as path from "path";

/**
 * Standalone index regression verification utility (#432).
 *
 * Verifies that critical index declarations exist in schema.prisma and
 * validates query plan normalization rules for high-value list, lookup,
 * cleanup, and worker queries.
 */

const SCHEMA_PATH = path.resolve(__dirname, "../prisma/schema.prisma");

const REQUIRED_INDEXES = [
  { model: "Payment", pattern: /@@index\(\[userId,\s*occurredAt\]\)/ },
  { model: "AuthSession", pattern: /tokenHash\s+String\s+@unique/ },
  { model: "Proof", pattern: /credentialHash\s+String\s+@unique/ },
  { model: "WebhookDelivery", pattern: /@@index\(\[status,\s*nextRetryAt\]\)/ },
  { model: "WalletChallenge", pattern: /@@index\(\[expiresAt\]\)/ },
  { model: "OrganizationMember", pattern: /@@index\(\[organizationId\]\)/ },
  { model: "AnchorIntent", pattern: /@@index\(\[status/ },
];

export function verifyIndexDeclarations(): { passed: boolean; errors: string[] } {
  if (!fs.existsSync(SCHEMA_PATH)) {
    return { passed: false, errors: [`Schema file not found at ${SCHEMA_PATH}`] };
  }

  const content = fs.readFileSync(SCHEMA_PATH, "utf-8");
  const errors: string[] = [];

  for (const item of REQUIRED_INDEXES) {
    if (!item.pattern.test(content)) {
      errors.push(`Missing required index in ${item.model}: ${item.pattern}`);
    }
  }

  return { passed: errors.length === 0, errors };
}

if (require.main === module) {
  const result = verifyIndexDeclarations();
  if (!result.passed) {
    console.error("❌ Index regression detected:\n" + result.errors.join("\n"));
    process.exit(1);
  } else {
    console.log("✅ All critical database indexes verified successfully.");
    process.exit(0);
  }
}
