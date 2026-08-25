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
