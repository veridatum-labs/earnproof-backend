import {
  DEFAULT_WEBHOOK_SKEW_POLICY,
  signWebhookPayload,
  verifyWebhookSignature,
} from "../../src/webhooks/webhook-signing.service";
import { verifyLockfileProvenance } from "../../scripts/verify-provenance";
import { evaluateLicensePolicy } from "../../scripts/license-policy";
import { scanFixtureContents } from "../../scripts/scan-fixtures";

describe("Webhook skew, provenance, license policy, and fixture scanner (#441-#444)", () => {
  test("#444 enforces past/future skew boundaries and preserves deliveryId on retry", () => {
    const baseMs = Date.parse("2026-11-25T08:00:00Z");
    const nowSec = Math.floor(baseMs / 1000);
    const body = JSON.stringify({ event: "proof.verified", id: "evt_1" });
    const secret = "test_signing_secret_value";
    const deliveryId = "deliv_fixed_001";

    // Sign at the oldest allowed past boundary (age == maxPastSkewSeconds).
    const pastBoundarySec = nowSec - DEFAULT_WEBHOOK_SKEW_POLICY.maxPastSkewSeconds;
    const pastSigned = signWebhookPayload({
      secret,
      deliveryId,
      rawBody: body,
      timestampSec: pastBoundarySec,
      nowMs: baseMs,
    });
    expect(pastSigned.deliveryId).toBe(deliveryId);

    const atPastBoundary = verifyWebhookSignature({
      secret,
      deliveryId: pastSigned.deliveryId,
      timestampSec: pastBoundarySec,
      signatureHex: pastSigned.signature,
      rawBody: body,
      nowMs: baseMs,
    });
    expect(atPastBoundary.valid).toBe(true);

    const staleSec = pastBoundarySec - 1;
    const staleSigned = signWebhookPayload({
      secret,
      deliveryId,
      rawBody: body,
      timestampSec: staleSec,
      nowMs: baseMs,
    });
    const staleResult = verifyWebhookSignature({
      secret,
      deliveryId: staleSigned.deliveryId,
      timestampSec: staleSec,
      signatureHex: staleSigned.signature,
      rawBody: body,
      nowMs: baseMs,
    });
    expect(staleResult.valid).toBe(false);
    expect(staleResult.reason).toBe("STALE_TIMESTAMP");

    // Sign at the newest allowed future boundary (timestamp == now + maxFutureSkewSeconds).
    const futureBoundarySec = nowSec + DEFAULT_WEBHOOK_SKEW_POLICY.maxFutureSkewSeconds;
    const futureSigned = signWebhookPayload({
      secret,
      deliveryId,
      rawBody: body,
      timestampSec: futureBoundarySec,
      nowMs: baseMs,
    });
    const atFutureBoundary = verifyWebhookSignature({
      secret,
      deliveryId: futureSigned.deliveryId,
      timestampSec: futureBoundarySec,
      signatureHex: futureSigned.signature,
      rawBody: body,
      nowMs: baseMs,
    });
    expect(atFutureBoundary.valid).toBe(true);

    const farFutureSec = futureBoundarySec + 1;
    const farFutureSigned = signWebhookPayload({
      secret,
      deliveryId,
      rawBody: body,
      timestampSec: farFutureSec,
      nowMs: baseMs,
    });
    const futureResult = verifyWebhookSignature({
      secret,
      deliveryId: farFutureSigned.deliveryId,
      timestampSec: farFutureSec,
      signatureHex: farFutureSigned.signature,
      rawBody: body,
      nowMs: baseMs,
    });
    expect(futureResult.valid).toBe(false);
    expect(futureResult.reason).toBe("FUTURE_TIMESTAMP");

    // Retry keeps the same deliveryId while updating the attempt timestamp.
    const retrySec = nowSec;
    const retrySigned = signWebhookPayload({
      secret,
      deliveryId,
      rawBody: body,
      timestampSec: retrySec,
      nowMs: baseMs,
    });
    expect(retrySigned.deliveryId).toBe(deliveryId);
    const retryResult = verifyWebhookSignature({
      secret,
      deliveryId: retrySigned.deliveryId,
      timestampSec: retrySec,
      signatureHex: retrySigned.signature,
      rawBody: body,
      nowMs: baseMs,
    });
    expect(retryResult.valid).toBe(true);

    // A fabricated signature is rejected in constant time.
    const tampered = verifyWebhookSignature({
      secret,
      deliveryId,
      timestampSec: nowSec,
      signatureHex: "0".repeat(64),
      rawBody: body,
      nowMs: baseMs,
    });
    expect(tampered.valid).toBe(false);
    expect(tampered.reason).toBe("SIGNATURE_MISMATCH");
  });

  test("#443 fails closed on unexpected registry or missing integrity unless valid exception exists", () => {
    const lockfile = {
      packages: {
        "node_modules/evil-pkg": {
          name: "evil-pkg",
          resolved: "https://untrusted.example.com/evil-pkg.tgz",
          integrity: "",
        },
      },
    };
    const nowMs = Date.parse("2026-11-25T00:00:00Z");
    const res = verifyLockfileProvenance(lockfile, { nowMs });
    expect(res.ok).toBe(false);
    expect(res.violations.length).toBeGreaterThan(0);

    // A valid, non-expired, owner-reviewed exception covers the package.
    const withException = verifyLockfileProvenance(lockfile, {
      nowMs,
      exceptions: [
        {
          packageName: "evil-pkg",
          owner: "security-team",
          reason: "legacy mirror migration",
          expiresAt: "2027-01-01T00:00:00Z",
        },
      ],
    });
    expect(withException.ok).toBe(true);

    // An expired exception does not cover the package (fail closed).
    const expiredException = verifyLockfileProvenance(lockfile, {
      nowMs,
      exceptions: [
        {
          packageName: "evil-pkg",
          owner: "security-team",
          reason: "legacy mirror migration",
          expiresAt: "2026-01-01T00:00:00Z",
        },
      ],
    });
    expect(expiredException.ok).toBe(false);
  });

  test("#442 distinguishes dev vs runtime dependencies and rejects denied/unknown licenses", () => {
    const lockfile = {
      packages: {
        "node_modules/dev-only": { name: "dev-only", license: "GPL-3.0", dev: true },
        "node_modules/runtime-bad": { name: "runtime-bad", license: "AGPL-3.0", dev: false },
        "node_modules/runtime-unknown": { name: "runtime-unknown", dev: false },
      },
    };
    const nowMs = Date.parse("2026-11-25T00:00:00Z");
    const res = evaluateLicensePolicy({
      lockfile,
      approvedLicenses: ["MIT", "Apache-2.0"],
      deniedLicenses: ["AGPL-3.0"],
      nowMs,
    });
    expect(res.ok).toBe(false);
    expect(res.violations).toHaveLength(2);
    expect(res.violations.map((v) => v.package).sort()).toEqual(["runtime-bad", "runtime-unknown"]);

    // Dev dependencies are not scanned.
    expect(res.violations.some((v) => v.package === "dev-only")).toBe(false);

    // Attribution report includes all runtime packages.
    expect(res.attribution).toHaveLength(2);
    expect(res.attribution.find((a) => a.package === "runtime-bad")?.overridden).toBe(false);

    // A valid, non-expired override clears a denied license.
    const overriddenLockfile = {
      packages: {
        "node_modules/dev-only": { name: "dev-only", license: "GPL-3.0", dev: true },
        "node_modules/runtime-bad": { name: "runtime-bad", license: "AGPL-3.0", dev: false },
      },
    };
    const overridden = evaluateLicensePolicy({
      lockfile: overriddenLockfile,
      approvedLicenses: ["MIT", "Apache-2.0"],
      deniedLicenses: ["AGPL-3.0"],
      nowMs,
      overrides: [
        {
          packageName: "runtime-bad",
          owner: "platform-team",
          rationale: "approved exception for legacy runtime",
          expiresAt: "2027-01-01T00:00:00Z",
        },
      ],
    });
    expect(overridden.ok).toBe(true);
    expect(overridden.attribution.find((a) => a.package === "runtime-bad")?.overridden).toBe(true);
  });

  test("#441 detects private keys in fixtures unless allowlisted with rationale", () => {
    const keyHeader = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
    const res = scanFixtureContents([
      { path: "test/fixtures/sample.pem", content: `${keyHeader}\nabc\n` },
    ]);
    expect(res.ok).toBe(false);
    expect(res.findings[0].patternId).toBe("PRIVATE_KEY_BLOCK");

    // A matching allowlist entry (path, patternId, value, non-empty rationale) allows the secret.
    const allowlisted = scanFixtureContents(
      [{ path: "test/fixtures/sample.pem", content: `${keyHeader}\nabc\n` }],
      {
        allowlist: [
          {
            path: "test/fixtures/sample.pem",
            patternId: "PRIVATE_KEY_BLOCK",
            value: keyHeader,
            rationale: "synthetic test fixture key, no production value",
          },
        ],
      }
    );
    expect(allowlisted.ok).toBe(true);

    // An empty rationale does not allowlist.
    const badAllowlist = scanFixtureContents(
      [{ path: "test/fixtures/sample.pem", content: `${keyHeader}\nabc\n` }],
      {
        allowlist: [
          {
            path: "test/fixtures/sample.pem",
            patternId: "PRIVATE_KEY_BLOCK",
            value: keyHeader,
            rationale: "",
          },
        ],
      }
    );
    expect(badAllowlist.ok).toBe(false);
  });
});
