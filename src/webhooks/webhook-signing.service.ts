/**
 * WebhookSigningService
 *
 * Responsible for:
 *  - generating per-endpoint signing secrets
 *  - computing HMAC-SHA256 signatures over outbound payloads
 *  - verifying inbound signatures (for integrator tooling / tests)
 *
 * ## Signing algorithm
 *
 * The signing base string is:
 *
 *   `${timestampSeconds}.${deliveryId}.${canonicalJsonBody}`
 *
 * where `canonicalJsonBody` is the result of `JSON.stringify(payload)` with
 * keys sorted recursively (same canonicalisation used for credential hashes).
 *
 * The HMAC-SHA256 of that string (keyed with the raw per-endpoint secret) is
 * hex-encoded and sent as:
 *
 *   X-EarnProof-Signature: sha256=<hex>
 *
 * Integrators verify by:
 *   1. Reading `X-EarnProof-Timestamp` and `X-EarnProof-Delivery`.
 *   2. Reconstructing `${ts}.${deliveryId}.${rawRequestBody}`.
 *   3. Computing `HMAC-SHA256(secret, reconstructed)` as hex.
 *   4. Comparing the result with the value after `sha256=` using a
 *      timing-safe equality function.
 */
import { Injectable } from "@nestjs/common";
import { createHmac, randomBytes } from "crypto";
import { safeEqual } from "../common/crypto/timing-safe";

@Injectable()
export class WebhookSigningService {
  /**
   * Generate a cryptographically random 32-byte signing secret.
   * Returns a URL-safe base64 string (43 characters).
   */
  generateSecret(): string {
    return randomBytes(32).toString("base64url");
  }

  /**
   * Compute the HMAC-SHA256 signature for an outbound delivery.
   *
   * @param secret       Raw (plaintext) per-endpoint signing secret.
   * @param timestamp    Unix timestamp in seconds (integer string).
   * @param deliveryId   Stable delivery UUID for this event.
   * @param body         The exact JSON string that will be sent as the request body.
   * @returns            Hex-encoded HMAC digest (no `sha256=` prefix).
   */
  sign(
    secret: string,
    timestamp: string,
    deliveryId: string,
    body: string,
  ): string {
    const signingBase = `${timestamp}.${deliveryId}.${body}`;
    return createHmac("sha256", secret).update(signingBase).digest("hex");
  }

  /**
   * Verify a signature received from an integrator or produced during a test.
   *
   * @param secret        Raw per-endpoint signing secret.
   * @param timestamp     Value from `X-EarnProof-Timestamp`.
   * @param deliveryId    Value from `X-EarnProof-Delivery`.
   * @param body          The raw request body string.
   * @param signature     The hex digest (without `sha256=` prefix).
   * @returns             true if the signature is valid, false otherwise.
   */
  verify(
    secret: string,
    timestamp: string,
    deliveryId: string,
    body: string,
    signature: string,
  ): boolean {
    const expected = this.sign(secret, timestamp, deliveryId, body);
    return safeEqual(expected, signature);
  }

  /**
   * Canonicalise a payload to a stable JSON string for signing.
   * Keys are sorted recursively (matches ProofsService.canonicalize).
   */
  canonicalize(payload: unknown): string {
    return JSON.stringify(this.sortObject(payload));
  }

  private sortObject(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((item) => this.sortObject(item));
    }
    if (value !== null && typeof value === "object") {
      const record = value as Record<string, unknown>;
      return Object.keys(record)
        .sort()
        .reduce<Record<string, unknown>>((acc, key) => {
          acc[key] = this.sortObject(record[key]);
          return acc;
        }, {});
    }
    return value;
  }
}
