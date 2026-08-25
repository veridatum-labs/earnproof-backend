import {
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { ProofsService } from "./proofs.service";

describe("ProofsService lifecycle", () => {
  it("creates, verifies, revokes, and re-verifies a minimum income proof", async () => {
    const store = createProofStore();
    const service = new ProofsService(store.prisma as never, {
      getOrThrow: jest.fn((key: string) => {
        const values: Record<string, string> = {
          credentialSigningSecret: "lifecycle-signing-secret",
          paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
          "stellar.network": "testnet",
        };
        return values[key];
      }),
    } as never);
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

  return {
    verificationEvents,
    prisma: {
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
        create: jest.fn(({ data }) => {
          const proof = {
            ...data,
            proofType: ProofType.MINIMUM_INCOME,
            status: data.status,
            createdAt: data.createdAt,
            revokedAt: null,
            user,
            claim: {
              ...data.claim.create,
            },
          };
          proofs.set(data.id, proof);
          return Promise.resolve(proof);
        }),
        findUnique: jest.fn(({ where }) => {
          const proof = proofs.get(where.id);
          return Promise.resolve(proof ?? null);
        }),
        update: jest.fn(({ where, data, select }) => {
          const proof = proofs.get(where.id);
          if (!proof) {
            return Promise.resolve(null);
          }

          const updated = {
            ...proof,
            ...data,
          };
          proofs.set(where.id, updated);

          return Promise.resolve(
            Object.keys(select).reduce<Record<string, unknown>>((result, key) => {
              result[key] = updated[key];
              return result;
            }, {}),
          );
        }),
      },
      verificationEvent: {
        create: jest.fn(({ data }) => {
          verificationEvents.push(data);
          return Promise.resolve({ id: `event_${verificationEvents.length}` });
        }),
      },
    },
  };
}

function protectAmount(amount: string) {
  return `redacted:${Buffer.from(amount).toString("base64url")}`;
}

// ---------------------------------------------------------------------------
// Recurring-income proof lifecycle
// ---------------------------------------------------------------------------
describe("ProofsService lifecycle – recurring-income", () => {
  it("creates, verifies, revokes, and re-verifies a recurring-income proof", async () => {
    const store = createRecurringProofStore();
    const service = new ProofsService(store.prisma as never, {
      getOrThrow: jest.fn((key: string) => {
        const values: Record<string, string> = {
          credentialSigningSecret: "lifecycle-signing-secret",
          paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
          "stellar.network": "testnet",
        };
        return values[key];
      }),
    } as never);
    const user = {
      id: "user_ri_lifecycle",
      walletAddress: "GB_TEST",
      walletHash: "sha256:ri-lifecycle-wallet",
      role: "WORKER",
    };

    // ── 1. Create ────────────────────────────────────────────────────────────
    const created = await service.createRecurringIncomeProof(user, {
      selectedPaymentIds: ["ri_payment_a", "ri_payment_b", "ri_payment_c"],
      intervalUnit: "month",
      intervalCount: 3,
      assetCode: "XLM",
      periodStart: "2026-04-01T00:00:00.000Z",
      periodEnd: "2026-06-30T23:59:59.000Z",
      expiresInDays: 7,
    });

    expect(created.status).toBe(ProofStatus.ACTIVE);
    expect(created.credential.type).toBe("EarnProofRecurringIncomeCredential");
    expect(created.credential.claim.intervalCount).toBe(3);
    expect(created.credential.claim.qualifyingPaymentCount).toBe(3);
    expect(created.credential.proof.credentialHash).toMatch(/^sha256:/);
    expect(created.credential.proof.signature).toMatch(/^hmac-sha256:/);

    // ── 2. Verify (valid) ────────────────────────────────────────────────────
    const firstVerification = await service.verifyProof(created.proofId);
    expect(firstVerification.result).toBe(VerificationResult.VALID);
    expect(firstVerification.status).toBe("valid");
    expect(firstVerification.credential!.type).toBe("EarnProofRecurringIncomeCredential");
    const claimAsRecurring = firstVerification.credential!.claim as {
      cadence: string;
      intervalUnit: string;
      intervalCount: number;
    };
    expect(claimAsRecurring.cadence).toBe("month:3");
    expect(store.verificationEvents).toHaveLength(1);

    // ── 3. Revoke ────────────────────────────────────────────────────────────
    const revoked = await service.revokeProof(user.id, created.proofId);
    expect(revoked.status).toBe(ProofStatus.REVOKED);

    // ── 4. Re-verify (revoked) ───────────────────────────────────────────────
    const secondVerification = await service.verifyProof(created.proofId);
    expect(secondVerification.result).toBe(VerificationResult.REVOKED);
    expect(secondVerification.status).toBe("revoked");
    expect(store.verificationEvents).toHaveLength(2);
  });
});

function createRecurringProofStore() {
  const user = {
    id: "user_ri_lifecycle",
    walletHash: "sha256:ri-lifecycle-wallet",
  };
  // Three payments, one per month, covering Apr / May / Jun 2026
  const payments = [
    {
      id: "ri_payment_a",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: protectAmount("300"),
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-04-15T00:00:00.000Z"),
    },
    {
      id: "ri_payment_b",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: protectAmount("310"),
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-05-15T00:00:00.000Z"),
    },
    {
      id: "ri_payment_c",
      userId: user.id,
      assetCode: "XLM",
      assetIssuer: null,
      amountEncrypted: protectAmount("290"),
      classification: PaymentClassification.INCOME,
      isEligible: true,
      occurredAt: new Date("2026-06-15T00:00:00.000Z"),
    },
  ];
  const proofs = new Map<string, Record<string, unknown>>();
  const verificationEvents: Record<string, unknown>[] = [];

  return {
    verificationEvents,
    prisma: {
      payment: {
        findMany: jest.fn(({ where }) =>
          Promise.resolve(
            payments.filter(
              (p) =>
                p.userId === where.userId &&
                where.id.in.includes(p.id),
            ),
          ),
        ),
      },
      proof: {
        create: jest.fn(({ data }) => {
          const proof = {
            ...data,
            status: data.status,
            createdAt: data.createdAt,
            revokedAt: null,
            user,
            claim: { ...data.claim.create },
          };
          proofs.set(data.id, proof);
          return Promise.resolve(proof);
        }),
        findUnique: jest.fn(({ where }) => {
          const proof = proofs.get(where.id);
          return Promise.resolve(proof ?? null);
        }),
        update: jest.fn(({ where, data, select }) => {
          const proof = proofs.get(where.id);
          if (!proof) return Promise.resolve(null);
          const updated = { ...proof, ...data };
          proofs.set(where.id, updated);
          return Promise.resolve(
            Object.keys(select).reduce<Record<string, unknown>>((result, key) => {
              result[key] = updated[key];
              return result;
            }, {}),
          );
        }),
      },
      verificationEvent: {
        create: jest.fn(({ data }) => {
          verificationEvents.push(data);
          return Promise.resolve({ id: `ri_event_${verificationEvents.length}` });
        }),
      },
    },
  };
}
