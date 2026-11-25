import { Injectable } from "@nestjs/common";
import { createHmac, timingSafeEqual } from "crypto";

/**
 * Webhook signing and verification.
 *
 * ## Signing scheme
 *
 * Algorithm: HMAC-SHA256
 *
 * Signing base string (all four parts joined with a literal `.`):
 *   `<unix-timestamp-seconds>.<deliveryId>.<keyId>.<raw-request-body>`
 *
 * Example:
 *   `1724400000.clxyz123.key_v1.{"specVersion":"1","id":"clxyz123",...}`
 *
 * ## Request headers sent on every delivery
 *
 * | Header                    | Value                                      |
 * |---------------------------|--------------------------------------------|
 * | `X-EarnProof-Timestamp`   | Unix timestamp in seconds (string)         |
 * | `X-EarnProof-Delivery`    | Delivery ID (cuid)                         |
 * | `X-EarnProof-Event`       | Event type, e.g. `proof.created`           |
 * | `X-EarnProof-Signature`   | `v1.key_id=<hex-encoded-HMAC-SHA256>`     |
 * | `Content-Type`            | `application/json`                         |
 *
 * ## Integrator verification procedure
 *
 * 1. Read `X-EarnProof-Timestamp`, `X-EarnProof-Delivery`, and `X-EarnProof-Signature` from headers.
 * 2. Extract keyId from signature: split on `=` and take the part after `v1.`.
 * 3. Look up the signing secret for this webhook using the keyId.
 * 4. Construct the signing base string:
 *    `timestamp + "." + deliveryId + "." + keyId + "." + rawRequestBody`
 * 5. Compute `HMAC-SHA256(signingSecret, baseString)` and hex-encode.
 * 6. Prepend `v1.keyId=` and compare with `X-EarnProof-Signature` using a
 *    constant-time comparison.
 * 7. Optionally reject requests where the timestamp is more than 5 minutes
 *    old to prevent replay attacks.
 */
@Injectable()
export class WebhookSigningService {
  /**
   * Compute the signature header value for an outbound delivery.
   *
   * @param secret      Raw (decrypted) signing secret for the endpoint.
   * @param timestamp   Unix timestamp in seconds.
   * @param deliveryId  Delivery ID (cuid).
   * @param keyId       Non-secret key identifier (from WebhookSecretVersion).
   * @param body        Serialised JSON request body.
   */
  sign(
    secret: string,
    timestamp: number,
    deliveryId: string,
    keyId: string,
    body: string,
  ): string;
  sign(
    secret: string,
    timestamp: number,
    deliveryId: string,
    body: string,
  ): string;
  sign(
    secret: string,
    timestamp: number,
    deliveryId: string,
    keyIdOrBody: string,
    maybeBody?: string,
  ): string {
    if (maybeBody !== undefined) {
      const keyId = keyIdOrBody;
      const body = maybeBody;
      const baseString = `${timestamp}.${deliveryId}.${keyId}.${body}`;
      const digest = createHmac("sha256", secret)
        .update(baseString, "utf8")
        .digest("hex");
      return `v1.${keyId}=${digest}`;
    }

    const body = keyIdOrBody;
    const baseString = `${timestamp}.${deliveryId}.${body}`;
    const digest = createHmac("sha256", secret)
      .update(baseString, "utf8")
      .digest("hex");
    return `v1=${digest}`;
  }

  /**
   * Verify an inbound signature (used in tests and by integrators).
   *
   * Returns `true` only when the computed digest matches the supplied
   * signature in constant time.
   *
   * Extracts keyId from the signature header for key identification.
   */
  verify(
    secret: string,
    timestamp: number,
    deliveryId: string,
    keyId: string,
    body: string,
    signature: string,
  ): boolean;
  verify(
    secret: string,
    timestamp: number,
    deliveryId: string,
    body: string,
    signature: string,
  ): boolean;
  verify(
    secret: string,
    timestamp: number,
    deliveryId: string,
    arg4: string,
    arg5: string,
    arg6?: string,
  ): boolean {
    let expected: string;
    let actual: string;

    if (arg6 !== undefined) {
      const keyId = arg4;
      const body = arg5;
      actual = arg6;
      expected = this.sign(secret, timestamp, deliveryId, keyId, body);
    } else {
      const body = arg4;
      actual = arg5;
      const keyId = this.extractKeyId(actual);
      expected = keyId
        ? this.sign(secret, timestamp, deliveryId, keyId, body)
        : this.sign(secret, timestamp, deliveryId, body);
    }

    try {
      return timingSafeEqual(
        Buffer.from(expected, "utf8"),
        Buffer.from(actual, "utf8"),
      );
    } catch {
      // Buffers differ in length — definitely not equal.
      return false;
    }
  }

  /**
   * Extract the keyId from a signature header.
   *
   * Expected format: `v1.<keyId>=<digest>`
   * Returns null if signature format is invalid.
   */
  extractKeyId(signature: string): string | null {
    const match = signature.match(/^v1\.([^=]+)=/);
    return match ? match[1] : null;
  }
}

/**
 * Webhook signing timestamp skew policy (#444).
 *
 * Versioned envelope with a stable delivery identity: the signed payload is
 * `v1.<deliveryId>.<timestampSec>.<body>`, so retries keep the same deliveryId
 * while updating the attempt timestamp. Timestamps are checked against a
 * configurable past/future skew window (inclusive of the boundary) and HMAC
 * digests are compared in constant time over equal-length buffers.
 */

export interface WebhookSkewPolicy {
  maxPastSkewSeconds: number;
  maxFutureSkewSeconds: number;
}

export interface SignedWebhookEnvelope {
  version: "v1";
  deliveryId: string;
  timestampSec: number;
  signature: string;
}

export const DEFAULT_WEBHOOK_SKEW_POLICY: WebhookSkewPolicy = {
  maxPastSkewSeconds: 300,
  maxFutureSkewSeconds: 60,
};

export function buildSigningPayload(
  version: string,
  deliveryId: string,
  timestampSec: number,
  rawBody: string | Buffer,
): string {
  const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : rawBody;
  return `${version}.${deliveryId}.${timestampSec}.${bodyString}`;
}

export function signWebhookPayload(params: {
  secret: string;
  deliveryId: string;
  rawBody: string | Buffer;
  timestampSec?: number;
  nowMs?: number;
}): SignedWebhookEnvelope {
  const version = "v1" as const;
  const nowMs = params.nowMs ?? Date.now();
  const timestampSec = params.timestampSec ?? Math.floor(nowMs / 1000);
  const payload = buildSigningPayload(version, params.deliveryId, timestampSec, params.rawBody);
  const signature = createHmac("sha256", params.secret).update(payload, "utf8").digest("hex");

  return {
    version,
    deliveryId: params.deliveryId,
    timestampSec,
    signature,
  };
}

export function verifyWebhookSignature(params: {
  secret: string;
  deliveryId: string;
  timestampSec: number;
  signatureHex: string;
  rawBody: string | Buffer;
  policy?: WebhookSkewPolicy;
  nowMs?: number;
}): { valid: boolean; reason?: string } {
  const policy = params.policy ?? DEFAULT_WEBHOOK_SKEW_POLICY;
  const nowSec = Math.floor((params.nowMs ?? Date.now()) / 1000);

  if (!Number.isInteger(params.timestampSec)) {
    return { valid: false, reason: "INVALID_TIMESTAMP" };
  }

  const ageSeconds = nowSec - params.timestampSec;
  if (ageSeconds > policy.maxPastSkewSeconds) {
    return { valid: false, reason: "STALE_TIMESTAMP" };
  }

  if (params.timestampSec - nowSec > policy.maxFutureSkewSeconds) {
    return { valid: false, reason: "FUTURE_TIMESTAMP" };
  }

  const payload = buildSigningPayload("v1", params.deliveryId, params.timestampSec, params.rawBody);
  const expectedHex = createHmac("sha256", params.secret).update(payload, "utf8").digest("hex");

  const expectedBuf = Buffer.from(expectedHex, "hex");
  const providedBuf = Buffer.from(params.signatureHex, "hex");

  if (expectedBuf.length === 0 || expectedBuf.length !== providedBuf.length) {
    return { valid: false, reason: "INVALID_SIGNATURE_LENGTH" };
  }

  const matched = timingSafeEqual(expectedBuf, providedBuf);
  return matched ? { valid: true } : { valid: false, reason: "SIGNATURE_MISMATCH" };
}
