import {
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { sha256 } from "../common/crypto/hash";
import { ProofsService } from "./proofs.service";
import { VerificationEventService } from "../audit/verification-event.service";

describe("ProofsService", () => {
  const config = {
    getOrThrow: jest.fn((key: string) => {
      const values: Record<string, string> = {
        credentialSigningSecret: "test-signing-secret",
        paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "stellar.network": "testnet",
      };
      return values[key];
    }),
  };

  const mockVerificationEventService = {
    recordEvent: jest.fn().mockResolvedValue(undefined),
    getAggregateStats: jest.fn().mockResolvedValue({}),
    cleanupExpiredEvents: jest.fn().mockResolvedValue(0),
  } as unknown as VerificationEventService;

  const user = {
    id: "user_1",
    walletAddress: "GB_TEST",
    walletHash: "sha256:wallet",
    role: "WORKER",
  };

  it("creates a signed minimum income proof without disclosing exact income", async () => {
    const prisma = {
      payment: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: "payment_1",
            assetCode: "XLM",
            assetIssuer: null,
            amountEncrypted: `redacted:${Buffer.from("125.50").toString(
              "base64url",
            )}`,
            classification: PaymentClassification.INCOME,
            isEligible: true,
            occurredAt: new Date("2026-08-01T00:00:00.000Z"),
          },
        ]),
      },
      proof: {
        create: jest.fn().mockImplementation(({ data }) => ({
          id: data.id,
          userId: data.userId,
          proofType: data.proofType,
          schemaVersion: data.schemaVersion,
          status: data.status,
          network: data.network,
          assetCode: data.assetCode,
          assetIssuer: data.assetIssuer,
          periodStart: data.periodStart,
          periodEnd: data.periodEnd,
          expiresAt: data.expiresAt,
          credentialHash: data.credentialHash,
          commitment: data.commitment,
          createdAt: data.createdAt,
          claim: data.claim.create,
        })),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    const result = await service.createMinimumIncomeProof(user, {
      selectedPaymentIds: ["payment_1"],
      thresholdAmount: "100",
      assetCode: "XLM",
      periodStart: "2026-08-01T00:00:00.000Z",
      periodEnd: "2026-08-31T23:59:59.000Z",
      expiresInDays: 10,
    });

    expect(result.status).toBe(ProofStatus.ACTIVE);
    expect(result.credential.claim.thresholdAmount).toBe("100");
    expect(result.credential.claim.qualifyingPaymentCount).toBe(1);
    expect(JSON.stringify(result)).not.toContain("125.50");
    expect(JSON.stringify(result)).not.toContain("payment_1");
    expect(result.credential.proof.signature).toMatch(/^hmac-sha256:/);
    expect(prisma.proof.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          proofType: ProofType.MINIMUM_INCOME,
          credentialHash: expect.stringMatching(/^sha256:/),
          commitment: expect.stringMatching(/^sha256:/),
          createdAt: expect.any(Date),
        }),
      }),
    );
  });

  it("rejects selected payments below the requested threshold", async () => {
    const prisma = {
      payment: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: "payment_1",
            assetCode: "XLM",
            assetIssuer: null,
            amountEncrypted: `redacted:${Buffer.from("25").toString(
              "base64url",
            )}`,
            classification: PaymentClassification.INCOME,
            isEligible: true,
            occurredAt: new Date("2026-08-01T00:00:00.000Z"),
          },
        ]),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    await expect(
      service.createMinimumIncomeProof(user, {
        selectedPaymentIds: ["payment_1"],
        thresholdAmount: "100",
        assetCode: "XLM",
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
      }),
    ).rejects.toThrow("minimum income threshold");
  });

  it("returns an unknown public verification state for missing proofs", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue(null),
      },
      verificationEventLog: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    await expect(service.verifyProof("missing")).resolves.toEqual({
      result: VerificationResult.UNKNOWN_PROOF,
      status: "unknown",
    });
  });

  it("returns a revoked public verification state", async () => {
    const credential = {
      id: "proof_1",
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: "earnproof.minimum-income.v1",
      issuer: "earnproof-backend",
      subject: {
        walletHash: "sha256:wallet",
      },
      claim: {
        operator: "gte",
        thresholdAmount: "100",
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
        qualifyingPaymentCount: 1,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: "2026-08-02T00:00:00.000Z",
      expiresAt: "2026-09-01T00:00:00.000Z",
    };
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_1",
          proofType: ProofType.MINIMUM_INCOME,
          schemaVersion: "earnproof.minimum-income.v1",
          status: ProofStatus.REVOKED,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: new Date("2026-08-01T00:00:00.000Z"),
          periodEnd: new Date("2026-08-31T23:59:59.000Z"),
          expiresAt: new Date("2026-09-01T00:00:00.000Z"),
          revokedAt: new Date("2026-08-03T00:00:00.000Z"),
          createdAt: new Date("2026-08-02T00:00:00.000Z"),
          credentialHash: `sha256:${sha256(canonicalize(credential))}`,
          user: {
            walletHash: "sha256:wallet",
          },
          claim: {
            thresholdEncrypted: `redacted:${Buffer.from("100").toString(
              "base64url",
            )}`,
            disclosurePolicy: {
              qualifyingPaymentCount: 1,
            },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never, mockVerificationEventService);

    const result = await service.verifyProof("proof_1");

    expect(result.result).toBe(VerificationResult.REVOKED);
    expect(result.status).toBe("revoked");
    expect(prisma.verificationEvent.create).toHaveBeenCalledWith({
      data: {
        proofId: "proof_1",
        result: VerificationResult.REVOKED,
      },
    });
  });

  it("revokes anchored proofs on-chain when contract anchoring is available", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_anchored",
          userId: "user_1",
          status: ProofStatus.ACTIVE,
          contractTransactionHash: "tx_register",
        }),
        update: jest.fn().mockResolvedValue({
          id: "proof_anchored",
          status: ProofStatus.REVOKED,
          revokedAt: new Date("2026-08-04T00:00:00.000Z"),
        }),
      },
    };
    const anchoring = {
      revokeProof: jest.fn().mockResolvedValue({
        anchored: true,
        transactionHash: "tx_revoke",
      }),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
      anchoring as never,
    );

    await expect(service.revokeProof("user_1", "proof_anchored")).resolves.toEqual(
      expect.objectContaining({
        id: "proof_anchored",
        anchoring: {
          anchored: true,
          transactionHash: "tx_revoke",
        },
      }),
    );
    expect(anchoring.revokeProof).toHaveBeenCalledWith("proof_anchored");
  });

  it("uses revoked on-chain status during public verification", async () => {
    const credential = {
      id: "proof_onchain_revoked",
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: "earnproof.minimum-income.v1",
      issuer: "earnproof-backend",
      subject: {
        walletHash: "sha256:wallet",
      },
      claim: {
        operator: "gte",
        thresholdAmount: "100",
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: "2026-08-01T00:00:00.000Z",
        periodEnd: "2026-08-31T23:59:59.000Z",
        qualifyingPaymentCount: 1,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: "2026-08-02T00:00:00.000Z",
      expiresAt: "2026-09-01T00:00:00.000Z",
    };
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_onchain_revoked",
          proofType: ProofType.MINIMUM_INCOME,
          schemaVersion: "earnproof.minimum-income.v1",
          status: ProofStatus.ACTIVE,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: new Date("2026-08-01T00:00:00.000Z"),
          periodEnd: new Date("2026-08-31T23:59:59.000Z"),
          expiresAt: new Date("2026-09-01T00:00:00.000Z"),
          revokedAt: null,
          createdAt: new Date("2026-08-02T00:00:00.000Z"),
          credentialHash: `sha256:${sha256(canonicalize(credential))}`,
          contractTransactionHash: "tx_register",
          user: {
            walletHash: "sha256:wallet",
          },
          claim: {
            thresholdEncrypted: `redacted:${Buffer.from("100").toString(
              "base64url",
            )}`,
            disclosurePolicy: {
              qualifyingPaymentCount: 1,
            },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    };
    const anchoring = {
      getProofStatus: jest.fn().mockResolvedValue({
        checked: true,
        revoked: true,
        valid: false,
      }),
    };
    const service = new ProofsService(
      prisma as never,
      config as never,
      mockVerificationEventService,
      anchoring as never,
    );

    const result = await service.verifyProof("proof_onchain_revoked");

    expect(result.result).toBe(VerificationResult.REVOKED);
    expect(result.status).toBe("revoked");
    expect(result.proof?.contractStatus).toEqual({
      checked: true,
      revoked: true,
      valid: false,
    });
  });
});

function canonicalize(value: unknown): string {
  return JSON.stringify(sortObject(value));
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortObject(item));
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.keys(record)
      .sort()
      .reduce<Record<string, unknown>>((sorted, key) => {
        sorted[key] = sortObject(record[key]);
        return sorted;
      }, {});
  }

  return value;
}

// ---------------------------------------------------------------------------
// Recurring-income proof tests
// ---------------------------------------------------------------------------
describe("ProofsService – recurring-income", () => {
  const config = {
    getOrThrow: jest.fn((key: string) => {
      const values: Record<string, string> = {
        credentialSigningSecret: "test-signing-secret",
        paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "stellar.network": "testnet",
      };
      return values[key];
    }),
  };

  const user = {
    id: "user_1",
    walletAddress: "GB_TEST",
    walletHash: "sha256:wallet",
    role: "WORKER",
  };

  // Helper: build a mock Payment that satisfies all eligibility constraints.
  function makePayment(overrides: Partial<{
    id: string;
    userId: string;
    assetCode: string;
    assetIssuer: string | null;
    classification: PaymentClassification;
    isEligible: boolean;
    occurredAt: Date;
  }> = {}) {
    return {
      id: "payment_1",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: `redacted:${Buffer.from("200").toString("base64url")}`,
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-06-15T00:00:00.000Z"),
      ...overrides,
    };
  }

  function makePrisma(payments: ReturnType<typeof makePayment>[]) {
    return {
      payment: {
        findMany: jest.fn().mockResolvedValue(payments),
      },
      proof: {
        create: jest.fn().mockImplementation(({ data }) => ({
          id: data.id,
          userId: data.userId,
          proofType: data.proofType,
          schemaVersion: data.schemaVersion,
          status: data.status,
          network: data.network,
          assetCode: data.assetCode,
          assetIssuer: data.assetIssuer,
          periodStart: data.periodStart,
          periodEnd: data.periodEnd,
          expiresAt: data.expiresAt,
          credentialHash: data.credentialHash,
          commitment: data.commitment,
          createdAt: data.createdAt,
          claim: data.claim.create,
        })),
      },
    };
  }

  // ── 1. Complete cadence → issues valid proof ──────────────────────────────
  it("issues a valid proof when all intervals are satisfied", async () => {
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-15T00:00:00.000Z") }),
      makePayment({ id: "p3", occurredAt: new Date("2026-06-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["p1", "p2", "p3"],
      intervalUnit: "month",
      intervalCount: 3,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-06-30T23:59:59.000Z",
      expiresInDays: 30,
    });

    expect(result.status).toBe(ProofStatus.ACTIVE);
    expect(result.credential!.type).toBe("EarnProofRecurringIncomeCredential");
    expect(result.credential!.schemaVersion).toBe("earnproof.recurring-income.v1");
    const claimAsRecurring = result.credential!.claim as {
      cadence: string;
      intervalUnit: string;
      intervalCount: number;
    };
    expect(claimAsRecurring.intervalUnit).toBe("month");
    expect(claimAsRecurring.intervalCount).toBe(3);
    expect(claimAsRecurring.cadence).toBe("month:3");
    expect(result.credential!.claim.qualifyingPaymentCount).toBe(3);
    expect(result.credential!.proof.signature).toMatch(/^hmac-sha256:/);
    expect(prisma.proof.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          proofType: ProofType.RECURRING_INCOME,
          schemaVersion: "earnproof.recurring-income.v1",
          credentialHash: expect.stringMatching(/^sha256:/),
          commitment: expect.stringMatching(/^sha256:/),
        }),
      }),
    );
  });

  // ── 2. Privacy: no exact income or transaction IDs in output ─────────────
  it("does not disclose source transactions or exact income amounts", async () => {
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["p1", "p2"],
      intervalUnit: "month",
      intervalCount: 2,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-05-31T23:59:59.000Z",
    });

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("200");      // exact income amount hidden
    expect(serialized).not.toContain("p1");        // payment ID hidden
    expect(serialized).not.toContain("p2");        // payment ID hidden
    expect(result.credential.privacy.exactIncomeHidden).toBe(true);
    expect(result.credential.privacy.sourceTransactionsHidden).toBe(true);
  });

  // ── 3. Missing interval → unsatisfied, no credential issued ──────────────
  it("rejects with unsatisfied error when any interval has no qualifying payment", async () => {
    // Only April and June covered – May is a gap
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-06-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    await expect(
      service.createRecurringIncomeProof(user, {
        selectedPaymentIds: ["p1", "p2"],
        intervalUnit: "month",
        intervalCount: 3,
        assetCode: "XLM",
        periodStart: "2026-04-01T00:00:00.000Z",
        periodEnd: "2026-06-30T23:59:59.000Z",
      }),
    ).rejects.toThrow("unsatisfied");
  });

  // ── 4. Boundary timestamps: payment exactly at interval edge ─────────────
  it("counts a payment that falls exactly on an interval start boundary", async () => {
    // Interval 0: [Apr 1, Apr 30 23:59:59.999]  – p1 at Apr 1 00:00:00 (start)
    // Interval 1: [May 1, May 31 23:59:59.000]  – p2 at May 31 23:59:59 (end)
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-01T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-31T23:59:59.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["p1", "p2"],
      intervalUnit: "month",
      intervalCount: 2,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-05-31T23:59:59.000Z",
    });

    expect(result.status).toBe(ProofStatus.ACTIVE);
    expect(result.credential.claim.qualifyingPaymentCount).toBe(2);
  });

  // ── 5. Wrong classification is excluded (validation rejects it) ───────────
  it("rejects payments that are not classified as INCOME", async () => {
    const payments = [
      makePayment({
        id: "p1",
        classification: PaymentClassification.REIMBURSEMENT,
        occurredAt: new Date("2026-04-15T00:00:00.000Z"),
      }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    await expect(
      service.createRecurringIncomeProof(user, {
        selectedPaymentIds: ["p1", "p2"],
        intervalUnit: "month",
        intervalCount: 2,
        assetCode: "XLM",
        periodStart: "2026-04-01T00:00:00.000Z",
        periodEnd: "2026-05-31T23:59:59.000Z",
      }),
    ).rejects.toThrow("eligible income payments");
  });

  // ── 6. Mixed assets are rejected ─────────────────────────────────────────
  it("rejects payments with a different asset code", async () => {
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({
        id: "p2",
        assetCode: "USDC",
        assetIssuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
        occurredAt: new Date("2026-05-15T00:00:00.000Z"),
      }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    await expect(
      service.createRecurringIncomeProof(user, {
        selectedPaymentIds: ["p1", "p2"],
        intervalUnit: "month",
        intervalCount: 2,
        assetCode: "XLM",
        periodStart: "2026-04-01T00:00:00.000Z",
        periodEnd: "2026-05-31T23:59:59.000Z",
      }),
    ).rejects.toThrow("requested asset");
  });

  // ── 7. Ownership scoping: payment not owned by requester is rejected ──────
  it("rejects when a selected payment does not belong to the requesting user", async () => {
    // prisma returns fewer payments than requested (ownership filter excludes one)
    const prisma = {
      payment: {
        findMany: jest.fn().mockResolvedValue([
          makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
          // p2 not returned because userId doesn't match
        ]),
      },
    };
    const service = new ProofsService(prisma as never, config as never);

    await expect(
      service.createRecurringIncomeProof(user, {
        selectedPaymentIds: ["p1", "p2"],
        intervalUnit: "month",
        intervalCount: 2,
        assetCode: "XLM",
        periodStart: "2026-04-01T00:00:00.000Z",
        periodEnd: "2026-05-31T23:59:59.000Z",
      }),
    ).rejects.toThrow("invalid");
  });

  // ── 8. Signing produces a valid HMAC on the credential ───────────────────
  it("signs the recurring-income credential with HMAC-SHA256", async () => {
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["p1", "p2"],
      intervalUnit: "month",
      intervalCount: 2,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-05-31T23:59:59.000Z",
    });

    expect(result.credential.proof.type).toBe("HMAC-SHA256");
    expect(result.credential.proof.credentialHash).toMatch(/^sha256:/);
    expect(result.credential.proof.signature).toMatch(/^hmac-sha256:/);

    // The credentialHash in the proof envelope must match a fresh computation
    const { proof: proofEnvelope, ...unsigned } = result.credential;
    expect(proofEnvelope.credentialHash).toBe(
      `sha256:${sha256(canonicalize(unsigned))}`,
    );
  });

  // ── 9. Revocation of a recurring-income proof ────────────────────────────
  it("revokes a recurring-income proof", async () => {
    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_ri",
          userId: user.id,
          status: ProofStatus.ACTIVE,
          contractTransactionHash: null,
        }),
        update: jest.fn().mockResolvedValue({
          id: "proof_ri",
          status: ProofStatus.REVOKED,
          revokedAt: new Date("2026-08-24T00:00:00.000Z"),
        }),
      },
    };
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.revokeProof(user.id, "proof_ri");

    expect(result.status).toBe(ProofStatus.REVOKED);
    expect(result.revokedAt).toBeDefined();
    expect(result.anchoring).toEqual({ anchored: false, reason: "disabled" });
  });

  // ── 10. Public verification validates cadence claims ────────────────────
  it("verifies a valid recurring-income proof and returns cadence claim", async () => {
    const issuedAt = new Date("2026-08-01T00:00:00.000Z");
    const expiresAt = new Date("2026-09-01T00:00:00.000Z");
    const periodStart = new Date("2026-04-01T00:00:00.000Z");
    const periodEnd = new Date("2026-06-30T23:59:59.000Z");

    // Build the exact credential the service would have built at issuance time
    const unsignedCredential = {
      id: "proof_ri_verify",
      type: "EarnProofRecurringIncomeCredential",
      schemaVersion: "earnproof.recurring-income.v1",
      issuer: "earnproof-backend",
      subject: { walletHash: "sha256:wallet" },
      claim: {
        cadence: "month:3",
        intervalUnit: "month",
        intervalCount: 3,
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: periodStart.toISOString(),
        periodEnd: periodEnd.toISOString(),
        qualifyingPaymentCount: 3,
      },
      privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true },
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_ri_verify",
          proofType: ProofType.RECURRING_INCOME,
          schemaVersion: "earnproof.recurring-income.v1",
          status: ProofStatus.ACTIVE,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart,
          periodEnd,
          expiresAt,
          revokedAt: null,
          createdAt: issuedAt,
          credentialHash: `sha256:${sha256(canonicalize(unsignedCredential))}`,
          contractTransactionHash: null,
          user: { walletHash: "sha256:wallet" },
          claim: {
            thresholdEncrypted: null,
            frequency: "month:3",
            disclosurePolicy: {
              exactIncomeHidden: true,
              sourceTransactionsHidden: true,
              qualifyingPaymentCount: 3,
              intervalUnit: "month",
              intervalCount: 3,
            },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_ri_1" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.verifyProof("proof_ri_verify");

    expect(result.result).toBe(VerificationResult.VALID);
    expect(result.status).toBe("valid");
    expect(result.credential!.type).toBe("EarnProofRecurringIncomeCredential");
    const claimAsRecurring2 = result.credential!.claim as {
      cadence: string;
      intervalUnit: string;
      intervalCount: number;
    };
    expect(claimAsRecurring2.cadence).toBe("month:3");
    expect(claimAsRecurring2.intervalCount).toBe(3);
    expect(result.proof?.schemaVersion).toBe("earnproof.recurring-income.v1");
    expect(result.proof?.type).toBe(ProofType.RECURRING_INCOME);
  });

  // ── 11. Verification rejects tampered recurring-income credentials ────────
  it("detects tampering and returns INVALID_SIGNATURE for a recurring-income proof", async () => {
    const issuedAt = new Date("2026-08-01T00:00:00.000Z");
    const expiresAt = new Date("2026-09-01T00:00:00.000Z");

    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_ri_tampered",
          proofType: ProofType.RECURRING_INCOME,
          schemaVersion: "earnproof.recurring-income.v1",
          status: ProofStatus.ACTIVE,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart: new Date("2026-04-01T00:00:00.000Z"),
          periodEnd: new Date("2026-06-30T23:59:59.000Z"),
          expiresAt,
          revokedAt: null,
          createdAt: issuedAt,
          // Hash of a DIFFERENT credential – simulates DB tampering
          credentialHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          contractTransactionHash: null,
          user: { walletHash: "sha256:wallet" },
          claim: {
            thresholdEncrypted: null,
            frequency: "month:3",
            disclosurePolicy: {
              qualifyingPaymentCount: 3,
              intervalUnit: "month",
              intervalCount: 3,
            },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_ri_2" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.verifyProof("proof_ri_tampered");

    expect(result.result).toBe(VerificationResult.INVALID_SIGNATURE);
    expect(result.status).toBe("invalid");
  });

  // ── 12. Verification returns REVOKED for a revoked recurring-income proof ─
  it("returns revoked status when verifying a revoked recurring-income proof", async () => {
    const issuedAt = new Date("2026-08-01T00:00:00.000Z");
    const expiresAt = new Date("2026-09-01T00:00:00.000Z");
    const periodStart = new Date("2026-04-01T00:00:00.000Z");
    const periodEnd = new Date("2026-06-30T23:59:59.000Z");

    const unsignedCredential = {
      id: "proof_ri_revoked",
      type: "EarnProofRecurringIncomeCredential",
      schemaVersion: "earnproof.recurring-income.v1",
      issuer: "earnproof-backend",
      subject: { walletHash: "sha256:wallet" },
      claim: {
        cadence: "month:3",
        intervalUnit: "month",
        intervalCount: 3,
        assetCode: "XLM",
        assetIssuer: null,
        periodStart: periodStart.toISOString(),
        periodEnd: periodEnd.toISOString(),
        qualifyingPaymentCount: 3,
      },
      privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true },
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    const prisma = {
      proof: {
        findUnique: jest.fn().mockResolvedValue({
          id: "proof_ri_revoked",
          proofType: ProofType.RECURRING_INCOME,
          schemaVersion: "earnproof.recurring-income.v1",
          status: ProofStatus.REVOKED,
          network: "testnet",
          assetCode: "XLM",
          assetIssuer: null,
          periodStart,
          periodEnd,
          expiresAt,
          revokedAt: new Date("2026-08-10T00:00:00.000Z"),
          createdAt: issuedAt,
          credentialHash: `sha256:${sha256(canonicalize(unsignedCredential))}`,
          contractTransactionHash: null,
          user: { walletHash: "sha256:wallet" },
          claim: {
            thresholdEncrypted: null,
            frequency: "month:3",
            disclosurePolicy: {
              qualifyingPaymentCount: 3,
              intervalUnit: "month",
              intervalCount: 3,
            },
          },
        }),
      },
      verificationEvent: {
        create: jest.fn().mockResolvedValue({ id: "event_ri_3" }),
      },
    };
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.verifyProof("proof_ri_revoked");

    expect(result.result).toBe(VerificationResult.REVOKED);
    expect(result.status).toBe("revoked");
  });

  // ── 13. Schema version distinguishes recurring-income from minimum-income ─
  it("uses a distinct schema version from minimum-income proofs", async () => {
    const payments = [
      makePayment({ id: "p1", occurredAt: new Date("2026-04-15T00:00:00.000Z") }),
      makePayment({ id: "p2", occurredAt: new Date("2026-05-15T00:00:00.000Z") }),
    ];
    const prisma = makePrisma(payments);
    const service = new ProofsService(prisma as never, config as never);

    const result = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["p1", "p2"],
      intervalUnit: "month",
      intervalCount: 2,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-05-31T23:59:59.000Z",
    });

    expect(result.credential.schemaVersion).toBe("earnproof.recurring-income.v1");
    expect(result.credential.schemaVersion).not.toBe("earnproof.minimum-income.v1");
    expect(result.credential.type).toBe("EarnProofRecurringIncomeCredential");
    expect(result.credential.type).not.toBe("EarnProofMinimumIncomeCredential");
  });
});
