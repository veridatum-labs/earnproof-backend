/**
 * Allowlisted webhook event types.
 *
 * Only these strings may appear in Webhook.events and WebhookDelivery.eventType.
 * New event types must be added here explicitly — arbitrary strings are rejected.
 */
export const WEBHOOK_EVENT_TYPES = [
  "proof.created",
  "proof.revoked",
  "proof.verified",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export function isWebhookEventType(value: unknown): value is WebhookEventType {
  return (
    typeof value === "string" &&
    (WEBHOOK_EVENT_TYPES as readonly string[]).includes(value)
  );
}

// ---------------------------------------------------------------------------
// Per-event payload shapes
//
// These include ONLY public/authorized fields. Private proof inputs (exact
// aggregate income amounts, source transaction IDs, payment operationIds,
// amountEncrypted values, thresholdEncrypted values) are never included.
// ---------------------------------------------------------------------------

export type ProofCreatedPayload = {
  /** Versioned payload discriminator */
  version: "earnproof.webhooks.v1";
  event: "proof.created";
  proofId: string;
  proofType: string;
  schemaVersion: string;
  network: string;
  assetCode: string;
  assetIssuer: string | null;
  status: string;
  /** ISO-8601 */
  expiresAt: string;
  /** ISO-8601 */
  createdAt: string;
  /** Integrators can use this to verify the proof independently */
  verificationUrl: string;
};

export type ProofRevokedPayload = {
  version: "earnproof.webhooks.v1";
  event: "proof.revoked";
  proofId: string;
  proofType: string;
  network: string;
  /** ISO-8601 */
  revokedAt: string;
};

export type ProofVerifiedPayload = {
  version: "earnproof.webhooks.v1";
  event: "proof.verified";
  proofId: string;
  proofType: string;
  network: string;
  /** One of: valid | expired | revoked | invalid | unknown */
  result: string;
  /** ISO-8601 */
  verifiedAt: string;
};

export type WebhookEventPayload =
  | ProofCreatedPayload
  | ProofRevokedPayload
  | ProofVerifiedPayload;
