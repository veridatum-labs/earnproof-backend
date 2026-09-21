import { ProofStatus, ProofType } from "@prisma/client";
import { VerificationEventService } from "../../src/audit/verification-event.service";
import { AuthenticatedUser } from "../../src/auth/auth.types";
import { ProofsService } from "../../src/proofs/proofs.service";
import { integrationDatabase } from "./harness/database";
import { integrationModule } from "./harness/nest";
import { seedPayment, seedUser } from "./harness/fixtures";

/**
 * Aggregate-earnings issuance against real PostgreSQL.
 *
 * The unit suite asserts the branching in `ProofsService` with a mocked Prisma
 * client. What it cannot assert is that the writes are legal: an
 * `AGGREGATE_EARNINGS` proof and its nested `ProofClaim` must satisfy the enum
 * types, the foreign keys, and the unique index on `credentialHash`. It also
 * cannot assert what PostgreSQL actually round-trips into the JSONB disclosure
 * policy — the privacy contract is about the stored row, not the in-memory
 * object.
 */

const db = integrationDatabase();
const injector = integrationModule([ProofsService, VerificationEventService]);

const PERIOD_START = "2025-01-01T00:00:00.000Z";
const PERIOD_END = "2025-12-31T23:59:59.000Z";

function proofs(): ProofsService {
  return injector.get(ProofsService);
}

async function userWithEarnings(seed: string) {
  const user = await seedUser(db.prisma, seed);

  const first = await seedPayment(db.prisma, `${seed}-1`, user.id, {
    amount: "600.0000000",
    assetCode: "USDC",
    assetIssuer: null,
    classification: "INCOME",
    isEligible: true,
    sourceAddress: `GSOURCE_${seed}_A`,
    occurredAt: new Date("2025-03-10T00:00:00.000Z"),
  });

  const second = await seedPayment(db.prisma, `${seed}-2`, user.id, {
    amount: "400.0000000",
    assetCode: "USDC",
    assetIssuer: null,
    classification: "INCOME",
    isEligible: true,
    sourceAddress: `GSOURCE_${seed}_B`,
    occurredAt: new Date("2025-08-20T00:00:00.000Z"),
  });

  const authenticated: AuthenticatedUser = {
    id: user.id,
    walletAddress: user.walletAddress,
    walletHash: user.walletHash,
    role: user.role,
  };

  return { user, authenticated, paymentIds: [first.row.id, second.row.id] };
}

describe("aggregate-earnings proof creation", () => {
  it("persists the proof and its aggregate claim in one transaction", async () => {
    const { authenticated, paymentIds } = await userWithEarnings("agg-create");

    const result = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: paymentIds,
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });

    const stored = await db.prisma.proof.findUniqueOrThrow({
      where: { id: result.proofId },
      include: { claim: true },
    });

    expect(stored.proofType).toBe(ProofType.AGGREGATE_EARNINGS);
    expect(stored.schemaVersion).toBe("earnproof.aggregate-earnings.v1");
    expect(stored.status).toBe(ProofStatus.ACTIVE);
    expect(stored.claim?.operator).toBe("sum");
    expect(stored.claim?.result).toBe(true);
  });

  it("stores a privacy-safe policy without component payments or sources", async () => {
    const { authenticated, paymentIds } = await userWithEarnings("agg-privacy");

    const result = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: paymentIds,
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });

    const claim = await db.prisma.proofClaim.findUniqueOrThrow({
      where: { proofId: result.proofId },
    });

    expect(claim.disclosurePolicy).toEqual({
      componentPaymentsHidden: true,
      sourceMetadataHidden: true,
      qualifyingPaymentCount: 2,
      sourceCount: 2,
      aggregationPolicyVersion: "aggregate-earnings-policy.v1",
    });

    const serialized = JSON.stringify(claim.disclosurePolicy);
    expect(serialized).not.toContain("GSOURCE");
    expect(serialized).not.toContain("600");
    expect(claim.thresholdEncrypted).toMatch(/^redacted:/);
  });

  it("counts a repeated payment id only once", async () => {
    const { authenticated, paymentIds } = await userWithEarnings("agg-dup");

    const result = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: [paymentIds[0], paymentIds[0], paymentIds[1]],
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });

    expect(result.credential.claim.totalAmount).toBe("1000.0000000");
    expect(result.credential.claim.qualifyingPaymentCount).toBe(2);
  });

  it("is deterministic regardless of the order ids are supplied", async () => {
    const { authenticated, paymentIds } = await userWithEarnings("agg-order");

    const forward = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: paymentIds,
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });
    const reversed = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: [...paymentIds].reverse(),
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });

    expect(forward.credential.claim).toEqual(reversed.credential.claim);
  });

  it("rejects a cross-asset selection", async () => {
    const { user, authenticated, paymentIds } =
      await userWithEarnings("agg-cross-asset");
    const xlm = await seedPayment(db.prisma, "agg-cross-asset-xlm", user.id, {
      amount: "50.0000000",
      assetCode: "XLM",
      assetIssuer: null,
      classification: "INCOME",
      isEligible: true,
      occurredAt: new Date("2025-04-01T00:00:00.000Z"),
    });

    await expect(
      proofs().createAggregateEarningsProof(authenticated, {
        selectedPaymentIds: [...paymentIds, xlm.row.id],
        assetCode: "USDC",
        periodStart: PERIOD_START,
        periodEnd: PERIOD_END,
      }),
    ).rejects.toThrow(/Cross-asset/);
  });

  it("verifies an issued aggregate proof through the shared pipeline", async () => {
    const { authenticated, paymentIds } = await userWithEarnings("agg-verify");

    const created = await proofs().createAggregateEarningsProof(authenticated, {
      selectedPaymentIds: paymentIds,
      assetCode: "USDC",
      periodStart: PERIOD_START,
      periodEnd: PERIOD_END,
    });

    const verification = await proofs().verifyProof(created.proofId);
    const credential = verification.credential as {
      claim: { totalAmount: string };
    };

    expect(verification.status).toBe("valid");
    expect(credential.claim.totalAmount).toBe("1000.0000000");
  });
});
