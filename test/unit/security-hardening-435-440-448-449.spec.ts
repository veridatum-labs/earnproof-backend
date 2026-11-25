import {
  buildSafeErrorEnvelope,
  scanRenderedOutputForSentinels,
} from "../src/common/observability/pii-leak-scanner";
import { PaymentTombstoneService, computeSourceIdentityCommitment } from "../src/payments/payment-tombstone.service";
import {
  computeProofEtag,
  getProofCacheControl,
  matchesIfNoneMatch,
  publicProofStatus,
} from "../src/proofs/proof-etag.policy";
import { validateRequestHost, normalizeHostHeader } from "../src/common/middleware/host-validation.middleware";

describe("security hardening (#435, #440, #448, #449)", () => {
  describe("#440 PII leak scanner", () => {
    const sentinels = [
      { category: "WALLET" as const, value: "GSECRETWALLET999999" },
      { category: "TOKEN" as const, value: "eyJhbGciOiJIUzI1NiJ9.secret.sig" },
      { category: "MEMO" as const, value: "Invoice-2026-01-01" },
      { category: "SIGNATURE" as const, value: "AAAA...SIGNATURE" },
      { category: "AMOUNT" as const, value: "12,345.67 USDC" },
    ];

    test("detects a sentinel leak in an error response without echoing the secret and preserves correlationId", () => {
      const leaks = scanRenderedOutputForSentinels({
        pathLabel: "POST /api/payments",
        outputKind: "ERROR_RESPONSE",
        payload: "Payment failed for GSECRETWALLET999999",
        sentinels,
        correlationId: "corr_123",
      });

      expect(leaks).toHaveLength(1);
      expect(leaks[0].pathLabel).toBe("POST /api/payments");
      expect(leaks[0].category).toBe("WALLET");
      expect(leaks[0].correlationId).toBe("corr_123");
      expect(JSON.stringify(leaks)).not.toContain("GSECRETWALLET999999");
    });

    test("scans structured payloads and plain-text strings alike", () => {
      const structured = scanRenderedOutputForSentinels({
        pathLabel: "GET /api/proofs/prf_1/verify",
        outputKind: "STRUCTURED_LOG",
        payload: { error: "invalid signature AAAA...SIGNATURE for wallet GSECRETWALLET999999" },
        sentinels,
        correlationId: "corr_log",
      });
      expect(structured).toHaveLength(2);

      const plain = scanRenderedOutputForSentinels({
        pathLabel: "POST /api/webhooks/stripe",
        outputKind: "PLAIN_TEXT_LOG",
        payload: "memo=Invoice-2026-01-01 amount=12,345.67 USDC",
        sentinels,
        correlationId: "corr_txt",
      });
      expect(plain).toHaveLength(2);
      expect(JSON.stringify(plain)).not.toContain("Invoice-2026-01-01");
      expect(JSON.stringify(plain)).not.toContain("12,345.67 USDC");
    });

    test("reports every sentinel found in a single output", () => {
      const leaks = scanRenderedOutputForSentinels({
        pathLabel: "POST /api/auth/verify",
        outputKind: "ERROR_RESPONSE",
        payload: "token eyJhbGciOiJIUzI1NiJ9.secret.sig rejected for GSECRETWALLET999999",
        sentinels,
        correlationId: "corr_auth",
      });
      expect(leaks.map((l) => l.category)).toEqual(["TOKEN", "WALLET"]);
    });

    test("returns no findings when no sentinel is present or payload is empty", () => {
      expect(
        scanRenderedOutputForSentinels({
          pathLabel: "GET /api/payments",
          outputKind: "ERROR_RESPONSE",
          payload: "Payment processed successfully",
          sentinels,
          correlationId: "corr_clean",
        }),
      ).toEqual([]);
      expect(
        scanRenderedOutputForSentinels({
          pathLabel: "GET /api/payments",
          outputKind: "ERROR_RESPONSE",
          payload: "",
          sentinels,
          correlationId: "corr_empty",
        }),
      ).toEqual([]);
      expect(
        scanRenderedOutputForSentinels({
          pathLabel: "GET /api/payments",
          outputKind: "ERROR_RESPONSE",
          payload: null,
          sentinels,
          correlationId: "corr_null",
        }),
      ).toEqual([]);
    });

    test("buildSafeErrorEnvelope carries correlationId and never the secret", () => {
      const envelope = buildSafeErrorEnvelope({
        statusCode: 400,
        code: "PAYMENT_FAILED",
        message: "Unable to process payment",
        correlationId: "corr_env",
      });
      expect(envelope.statusCode).toBe(400);
      expect(envelope.error.code).toBe("PAYMENT_FAILED");
      expect(envelope.error.correlationId).toBe("corr_env");
      expect(JSON.stringify(envelope)).not.toContain("GSECRETWALLET999999");
    });
  });

  describe("#449 payment deletion tombstones", () => {
    test("computeSourceIdentityCommitment is deterministic and input-sensitive", () => {
      const a = computeSourceIdentityCommitment({
        pepper: "p",
        ownerId: "u_1",
        accountId: "acc_1",
        paymentId: "pay_1",
      });
      const b = computeSourceIdentityCommitment({
        pepper: "p",
        ownerId: "u_1",
        accountId: "acc_1",
        paymentId: "pay_1",
      });
      expect(a).toBe(b);
      expect(a).not.toBe("");
      expect(a.length).toBe(64);

      const otherPayment = computeSourceIdentityCommitment({
        pepper: "p",
        ownerId: "u_1",
        accountId: "acc_1",
        paymentId: "pay_2",
      });
      const otherOwner = computeSourceIdentityCommitment({
        pepper: "p",
        ownerId: "u_2",
        accountId: "acc_1",
        paymentId: "pay_1",
      });
      const otherAccount = computeSourceIdentityCommitment({
        pepper: "p",
        ownerId: "u_1",
        accountId: "acc_2",
        paymentId: "pay_1",
      });
      expect(otherPayment).not.toBe(a);
      expect(otherOwner).not.toBe(a);
      expect(otherAccount).not.toBe(a);
      expect(otherPayment).not.toBe(otherOwner);
      expect(otherOwner).not.toBe(otherAccount);
    });

    test("blocks reingestion while tombstone is active and honors expiry", async () => {
      const records = new Map<string, { expiresAt: Date }>();
      let now = new Date("2026-11-25T00:00:00Z");
      const store = {
        upsert: async (rec: { ownerId: string; sourceIdentityCommitment: string; expiresAt: Date }) => {
          records.set(`${rec.ownerId}:${rec.sourceIdentityCommitment}`, rec);
        },
        findActive: async (ownerId: string, commitment: string, checkNow: Date) => {
          const rec = records.get(`${ownerId}:${commitment}`);
          if (!rec || checkNow.getTime() >= rec.expiresAt.getTime()) return null;
          return rec;
        },
      };

      const svc = new PaymentTombstoneService(store, "pepper_secret", () => now);
      await svc.recordDeletionTombstone({
        ownerId: "u_1",
        accountId: "acc_1",
        paymentId: "pay_1",
        retentionDays: 7,
        reason: "privacy",
      });

      expect(
        await svc.shouldBlockReingestion({ ownerId: "u_1", accountId: "acc_1", paymentId: "pay_1" }),
      ).toBe(true);

      // Owner-scoped: a different owner is not blocked.
      expect(
        await svc.shouldBlockReingestion({ ownerId: "u_2", accountId: "acc_1", paymentId: "pay_1" }),
      ).toBe(false);

      // After expiry, reingestion is no longer blocked.
      now = new Date("2026-12-03T00:00:01Z");
      expect(
        await svc.shouldBlockReingestion({ ownerId: "u_1", accountId: "acc_1", paymentId: "pay_1" }),
      ).toBe(false);

      // Boundary: exactly at expiry is not active.
      now = new Date("2026-12-02T00:00:00Z");
      expect(
        await svc.shouldBlockReingestion({ ownerId: "u_1", accountId: "acc_1", paymentId: "pay_1" }),
      ).toBe(false);
    });
  });

  describe("#448 proof verification ETag and revalidation", () => {
    test("ETag changes on every public status transition", () => {
      const active = computeProofEtag({
        proofId: "prf_1",
        status: "ACTIVE",
        updatedAtIso: "2026-11-25T00:00:00Z",
      });
      const revoked = computeProofEtag({
        proofId: "prf_1",
        status: "REVOKED",
        updatedAtIso: "2026-11-25T01:00:00Z",
      });
      const expired = computeProofEtag({
        proofId: "prf_1",
        status: "EXPIRED",
        updatedAtIso: "2026-11-25T02:00:00Z",
      });
      expect(active).toBe(`W/"${active.slice(3, -1)}"`);
      expect(active).not.toBe(revoked);
      expect(revoked).not.toBe(expired);
      expect(active).not.toBe(expired);

      // Same state → same ETag (conditional 304 eligible).
      expect(
        computeProofEtag({ proofId: "prf_1", status: "ACTIVE", updatedAtIso: "2026-11-25T00:00:00Z" }),
      ).toBe(active);
    });

    test("publicProofStatus maps public verification outcomes", () => {
      expect(publicProofStatus("valid")).toBe("ACTIVE");
      expect(publicProofStatus("expired")).toBe("EXPIRED");
      expect(publicProofStatus("revoked")).toBe("REVOKED");
      expect(publicProofStatus("unknown")).toBe("NOT_FOUND");
      expect(publicProofStatus("invalid")).toBe("ACTIVE");
      expect(publicProofStatus("garbage")).toBe("ACTIVE");
    });

    test("cache control is conservative and never serves revoked/expired/unknown from cache", () => {
      expect(getProofCacheControl("REVOKED")).toBe("no-store, must-revalidate");
      expect(getProofCacheControl("EXPIRED")).toBe("no-store, must-revalidate");
      expect(getProofCacheControl("NOT_FOUND")).toBe("no-store, must-revalidate");
      expect(getProofCacheControl("ACTIVE")).toBe("public, max-age=0, must-revalidate");
    });

    test("matches If-None-Match and rejects malformed tags safely", () => {
      const etag = computeProofEtag({
        proofId: "prf_1",
        status: "ACTIVE",
        updatedAtIso: "2026-11-25T00:00:00Z",
      });

      expect(matchesIfNoneMatch(etag, etag)).toBe(true);
      expect(matchesIfNoneMatch(`"${etag.slice(3, -1)}"`, etag)).toBe(true); // strong form
      expect(matchesIfNoneMatch("*", etag)).toBe(true);
      expect(matchesIfNoneMatch("malformed-etag-value", etag)).toBe(false);
      expect(matchesIfNoneMatch("W/\"deadbeef\"", etag)).toBe(false);
      expect(matchesIfNoneMatch(undefined, etag)).toBe(false);
      expect(matchesIfNoneMatch("", etag)).toBe(false);
      expect(matchesIfNoneMatch(`"${etag.slice(3, -1)}", W/"wrong"`, etag)).toBe(true); // list with one match
    });
  });

  describe("#435 host header and canonical origin validation", () => {
    const cfg = {
      enabled: true,
      allowedHosts: new Set(["api.earnproof.example", "localhost:3000", "[::1]:3000"]),
      canonicalOrigin: "https://api.earnproof.example",
      trustedProxies: new Set(["10.0.0.1"]),
    };

    test("rejects unknown and malformed hosts", () => {
      expect(
        validateRequestHost({ hostHeader: "evil.example", config: cfg }).ok,
      ).toBe(false);
      expect(
        validateRequestHost({ hostHeader: ["api.earnproof.example", "evil.example"], config: cfg }).ok,
      ).toBe(false); // duplicate header
      expect(
        validateRequestHost({ hostHeader: "api.earnproof.example/evil", config: cfg }).ok,
      ).toBe(false); // path separator
      expect(
        validateRequestHost({ hostHeader: " api.earnproof.example ", config: cfg }).ok,
      ).toBe(false); // whitespace
      expect(
        validateRequestHost({ hostHeader: "a,b", config: cfg }).ok,
      ).toBe(false); // comma
      expect(
        validateRequestHost({ hostHeader: "", config: cfg }).ok,
      ).toBe(false); // empty
      expect(
        validateRequestHost({ hostHeader: undefined, config: cfg }).ok,
      ).toBe(false); // missing
      expect(
        validateRequestHost({ hostHeader: "api.earnproof.example:99999", config: cfg }).ok,
      ).toBe(false); // bad port
    });

    test("normalizes case, IPv6, and ports", () => {
      expect(
        validateRequestHost({ hostHeader: "API.EARNPROOF.EXAMPLE", config: cfg }).ok,
      ).toBe(true); // case
      expect(
        validateRequestHost({ hostHeader: "[::1]:3000", config: cfg }).ok,
      ).toBe(true); // IPv6 with port
      expect(
        validateRequestHost({ hostHeader: "[::1]", config: cfg }).ok,
      ).toBe(true); // IPv6 without port
      expect(
        validateRequestHost({ hostHeader: "localhost:3000", config: cfg }).ok,
      ).toBe(true);
      expect(
        validateRequestHost({ hostHeader: "localhost:0", config: cfg }).ok,
      ).toBe(false); // port zero invalid
      expect(
        validateRequestHost({ hostHeader: ".api.earnproof.example", config: cfg }).ok,
      ).toBe(false); // leading dot
    });

    test("honors forwarded hosts only from trusted proxies (fail closed)", () => {
      const trusted = validateRequestHost({
        hostHeader: "api.earnproof.example",
        forwardedHostHeader: "api.earnproof.example",
        remoteAddress: "10.0.0.1",
        config: cfg,
      });
      expect(trusted.ok).toBe(true);
      expect(trusted.effectiveHost).toBe("api.earnproof.example");

      const untrusted = validateRequestHost({
        hostHeader: "api.earnproof.example",
        forwardedHostHeader: "api.earnproof.example",
        remoteAddress: "198.51.100.9",
        config: cfg,
      });
      expect(untrusted.ok).toBe(false);
      expect(untrusted.reason).toBe("UNTRUSTED_FORWARDED_HOST");

      const untrustedForwarded = validateRequestHost({
        hostHeader: "api.earnproof.example",
        forwardedHostHeader: "evil.example",
        remoteAddress: "10.0.0.1",
        config: cfg,
      });
      expect(untrustedForwarded.ok).toBe(false);
      expect(untrustedForwarded.reason).toBe("INVALID_OR_UNALLOWED_FORWARDED_HOST");
    });

    test("normalizeHostHeader rejects duplicates, whitespace, slashes, and bad IPv6", () => {
      expect(normalizeHostHeader(["a", "b"])).toBeNull();
      expect(normalizeHostHeader(" a b ")).toBeNull();
      expect(normalizeHostHeader("http://example.com")).toBeNull();
      expect(normalizeHostHeader("[::1")).toBeNull();
      expect(normalizeHostHeader("[::1]:-1")).toBeNull();
      expect(normalizeHostHeader("a:b:c")).toBeNull();
      expect(normalizeHostHeader("API.EARNPROOF.EXAMPLE")).toBe("api.earnproof.example");
    });

    test("regression: allowlisted host without forwarded header passes", () => {
      expect(
        validateRequestHost({ hostHeader: "api.earnproof.example", config: cfg }).ok,
      ).toBe(true);
    });
  });
});
