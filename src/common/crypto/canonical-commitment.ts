import { createHash, timingSafeEqual } from 'crypto';

export const COMMITMENT_VERSION = 'v1';

export interface CommitmentInput {
  version?: string;
  organizationId: string;
  webhookEndpointId: string;
  deliveryId: string;
  eventId: string;
  eventType: string;
  attemptedAtIso: string;
  payload: unknown;
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(record[k])}`).join(',')}}`;
}

export function computeWebhookCommitment(input: CommitmentInput): {
  commitmentVersion: string;
  commitmentHash: string;
  payloadByteLength: number;
  canonicalMetadata: Record<string, string | number>;
} {
  const version = input.version ?? COMMITMENT_VERSION;
  const canonicalPayload = canonicalizeJson(input.payload);
  const payloadByteLength = Buffer.byteLength(canonicalPayload, 'utf8');

  const canonicalMetadata = {
    commitmentVersion: version,
    deliveryId: input.deliveryId,
    eventId: input.eventId,
    eventType: input.eventType,
    attemptedAtIso: input.attemptedAtIso,
    payloadByteLength,
  };

  // Hash covers version, canonical metadata, and canonical payload — excludes signing secret
  const preimage = canonicalizeJson({
    v: version,
    org: input.organizationId,
    endpoint: input.webhookEndpointId,
    meta: canonicalMetadata,
    payloadSha256: createHash('sha256').update(canonicalPayload, 'utf8').digest('hex'),
  });

  const commitmentHash = createHash('sha256').update(preimage, 'utf8').digest('hex');

  return { commitmentVersion: version, commitmentHash, payloadByteLength, canonicalMetadata };
}

export function verifyWebhookCommitment(expectedHash: string, candidate: CommitmentInput): boolean {
  const { commitmentHash } = computeWebhookCommitment(candidate);
  const a = Buffer.from(expectedHash, 'hex');
  const b = Buffer.from(commitmentHash, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}