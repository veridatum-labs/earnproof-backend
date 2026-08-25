import {
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { ProofsService } from "./proofs.service";
import { VerificationEventService } from "../audit/verification-event.service";

describe("ProofsService lifecycle", () => {
  it("creates, verifies, revokes, and re-verifies a minimum income proof", async () => {
    const store = createProofStore();
    const mockVerificationEventService = {
      recordEvent: jest.fn().mockResolvedValue(undefined),
      getAggregateStats: jest.fn().mockResolvedValue({}),
      cleanupExpiredEvents: jest.fn().mockResolvedValue(0),
    } as unknown as VerificationEventService;
    const service = new ProofsService(store.prisma as never, {
      getOrThrow: jest.fn((key: string) => {
        const values: Record<string, string> = {
          credentialSigningSecret: "lifecycle-signing-secret",
          paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
          "stellar.network": "testnet",
        };
        return values[key];
      }),
    } as never, mockVerificationEventService);
    const user = {
      id: "user_lifecycle",
      walletAddress: "GB_TEST",
      walletHash: "sha256:lifecycle-wallet",
      role: "WORKER",
    };

    const created = await service.createMinimumIncomeProof(user, {
      selectedPaymentIds: ["payment_a", "payment_b"],
      thresholdAmount: "150",
      assetCode: "XLM",
      periodStart: "2026-08-01T00:00:00.000Z",
      periodEnd: "2026-08-31T23:59:59.000Z",
      expiresInDays: 7,
    });

    expect(created.status).toBe(ProofStatus.ACTIVE);
    expect(created.credential.claim.qualifyingPaymentCount).toBe(2);
    expect(created.credential.proof.credentialHash).toMatch(/^sha256:/);
    expect(created.credential.proof.signature).toMatch(/^hmac-sha256:/);

    const firstVerification = await service.verifyProof(created.proofId);
    expect(firstVerification.result).toBe(VerificationResult.VALID);
    expect(firstVerification.status).toBe("valid");
    expect(store.verificationEvents).toHaveLength(1);

    await service.revokeProof(user.id, created.proofId);

    const secondVerification = await service.verifyProof(created.proofId);
    expect(secondVerification.result).toBe(VerificationResult.REVOKED);
    expect(secondVerification.status).toBe("revoked");
    expect(store.verificationEvents).toHaveLength(2);
  });
});

function createProofStore() {
  const user = {
    id: "user_lifecycle",
    walletHash: "sha256:lifecycle-wallet",
  };
  const payments = [
    {
      id: "payment_a",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: protectAmount("100"),
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-08-03T00:00:00.000Z"),
    },
    {
      id: "payment_b",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: protectAmount("75"),
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-08-04T00:00:00.000Z"),
    },
  ];
  const proofs = new Map<string, Record<string, unknown>>();
  const verificationEvents: Record<string, unknown>[] = [];

  const prisma = {
    payment: {
      findMany: jest.fn(({ where }) =>
        Promise.resolve(
          payments.filter(
            (payment) =>
              payment.userId === where.userId &&
              where.id.in.includes(payment.id),
          ),
        ),
      ),
    },
    proof: {
      // Used by revokeProof (findUnique before update) and verifyProof.
      findUnique: jest.fn(({ where }) => {
        const proof = proofs.get(where.id);
        return Promise.resolve(proof ?? null);
      }),
      update: jest.fn(({ where, data, select }) => {
        const proof = proofs.get(where.id);
        if (!proof) {
          return Promise.resolve(null);
        }

        const updated = { ...proof, ...data };
        proofs.set(where.id, updated);

        return Promise.resolve(
          Object.keys(select).reduce<Record<string, unknown>>((result, key) => {
            result[key] = updated[key];
            return result;
          }, {}),
        );
      }),
      verificationEvent: {
        create: jest.fn(({ data }) => {
          verificationEvents.push(data);
          return Promise.resolve({ id: `event_${verificationEvents.length}` });
        }),
      },
      verificationEventLog: {
        create: jest.fn().mockResolvedValue({ id: "event_1" }),
      },
    },
    // $transaction is used by createMinimumIncomeProof and revokeProof.
    $transaction: jest.fn().mockImplementation(async (fn: (tx: unknown) => unknown) => {
      const tx = {
        proof: {
          create: jest.fn(({ data }) => {
            const proof = {
              ...data,
              proofType: ProofType.MINIMUM_INCOME,
              status: data.status,
              createdAt: data.createdAt,
              revokedAt: null,
              contractTransactionHash: null,
              user,
              claim: { ...data.claim.create },
            };
            proofs.set(data.id, proof);
            return Promise.resolve(proof);
          }),
          update: jest.fn(({ where, data, select }) => {
            const proof = proofs.get(where.id);
            if (!proof) return Promise.resolve(null);
            const updated = { ...proof, ...data };
            proofs.set(where.id, updated);
            if (!select) return Promise.resolve(updated);
            return Promise.resolve(
              Object.keys(select).reduce<Record<string, unknown>>((result, key) => {
                result[key] = updated[key];
                return result;
              }, {}),
            );
          }),
        },
        anchoringIntent: {
          create: jest.fn().mockResolvedValue({ id: "intent_1" }),
        },
      };
      return fn(tx);
    }),
  };

  return { verificationEvents, prisma };
}

function protectAmount(amount: string) {
  return `redacted:${Buffer.from(amount).toString("base64url")}`;
}
