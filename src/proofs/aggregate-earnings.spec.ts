import {
  PaymentClassification,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { ProofsService } from "./proofs.service";

const user = {
  id: "user_1",
  walletAddress: "GB_OWNER",
  walletHash: "sha256:owner",
  role: "WORKER",
};

const PERIOD_START = "2025-01-01T00:00:00.000Z";
const PERIOD_END = "2025-12-31T23:59:59.000Z";
const ASSET_CODE = "USDC";
const ASSET_ISSUER = "GISSUER";

interface PaymentRow {
  id: string;
  operationId: string;
  sourceAddress: string;
  assetCode: string;
  assetIssuer: string | null;
  amountEncrypted: string;
  classification: PaymentClassification;
  isEligible: boolean;
  occurredAt: Date;
}

function payment(overrides: Partial<PaymentRow> = {}): PaymentRow {
  return {
    id: "payment_1",
    operationId: "op_1",
    sourceAddress: "GSOURCE_A",
    assetCode: ASSET_CODE,
    assetIssuer: ASSET_ISSUER,
    amountEncrypted: encodeAmount("600.0000000"),
    classification: PaymentClassification.INCOME,
    isEligible: true,
    occurredAt: new Date("2025-06-01T00:00:00.000Z"),
    ...overrides,
  };
}

function encodeAmount(amount: string): string {
  return `redacted:${Buffer.from(amount).toString("base64url")}`;
}

function decodeProtected(value: string): string {
  return Buffer.from(value.slice("redacted:".length), "base64url").toString(
    "utf8",
  );
}

const events = {
  recordEvent: jest.fn().mockResolvedValue(undefined),
  getAggregateStats: jest.fn().mockResolvedValue({}),
};

function makeConfig(anchoring = false) {
  return {
    get: jest.fn((key: string) => {
      if (key === "contractAnchoring.enabled") return anchoring;
      if (key === "contractAnchoring.required") return false;
      return undefined;
    }),
    getOrThrow: jest.fn((key: string) => {
      const values: Record<string, string> = {
        credentialSigningSecret: "test-signing-secret",
        paymentEncryptionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "stellar.network": "testnet",
      };
      if (!(key in values)) throw new Error(`missing config ${key}`);
      return values[key];
    }),
  };
}

function harness(payments: PaymentRow[], anchoring = false) {
  let storedProof: Record<string, unknown> | undefined;
  const createdIntents: unknown[] = [];
  const prisma: any = {
    payment: { findMany: jest.fn().mockResolvedValue(payments) },
    proof: {
      create: jest.fn().mockImplementation(({ data }) => {
        storedProof = {
          ...data,
          updatedAt: data.createdAt,
          contractTransactionHash: null,
          revokedAt: null,
          user: { walletHash: user.walletHash },
          claim: {
            id: "claim_1",
            proofId: data.id,
            createdAt: data.createdAt,
            frequency: null,
            ...data.claim.create,
          },
        };
        return storedProof;
      }),
      findUnique: jest.fn().mockImplementation(() => storedProof),
    },
    verificationEvent: {
      create: jest.fn().mockResolvedValue({ id: "event_1" }),
    },
    anchoringIntent: {
      create: jest.fn().mockImplementation(({ data }) => {
        createdIntents.push(data);
        return { id: "intent_1", ...data };
      }),
    },
  };
  prisma.$transaction = jest.fn((callback: (tx: unknown) => unknown) =>
    callback(prisma),
  );
  const service = new ProofsService(
    prisma as never,
    makeConfig(anchoring) as never,
    events as never,
  );
  return {
    service,
    prisma,
    createdIntents,
    getStoredProof: () => storedProof!,
  };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    selectedPaymentIds: ["payment_1", "payment_2"],
    assetCode: ASSET_CODE,
    assetIssuer: ASSET_ISSUER,
    periodStart: PERIOD_START,
    periodEnd: PERIOD_END,
    ...overrides,
  };
}

const twoPayments: PaymentRow[] = [
  payment({
    id: "payment_1",
    operationId: "op_1",
    sourceAddress: "GSOURCE_A",
    amountEncrypted: encodeAmount("600.0000000"),
    occurredAt: new Date("2025-06-01T00:00:00.000Z"),
  }),
  payment({
    id: "payment_2",
    operationId: "op_2",
    sourceAddress: "GSOURCE_B",
    amountEncrypted: encodeAmount("400.0000000"),
    occurredAt: new Date("2025-07-01T00:00:00.000Z"),
  }),
];

describe("ProofsService aggregate-earnings proofs", () => {
  it("issues a credential committing the normalized total and policy version", async () => {
    const { service, getStoredProof } = harness(twoPayments);

    const result = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );

    expect(result.credential.type).toBe("EarnProofAggregateEarningsCredential");
    expect(result.credential.schemaVersion).toBe(
      "earnproof.aggregate-earnings.v1",
    );
    expect(result.credential.claim).toMatchObject({
      operator: "sum",
      totalAmount: "1000.0000000",
      assetCode: ASSET_CODE,
      assetIssuer: ASSET_ISSUER,
      qualifyingPaymentCount: 2,
      sourceCount: 2,
      aggregationPolicyVersion: "aggregate-earnings-policy.v1",
    });
    expect(result.credential.privacy).toEqual({
      componentPaymentsHidden: true,
      sourceMetadataHidden: true,
    });
    expect(result.credential.proof.signature).toMatch(/^hmac-sha256:/);

    const stored = getStoredProof();
    expect(stored.proofType).toBe(ProofType.AGGREGATE_EARNINGS);
    expect(stored.schemaVersion).toBe("earnproof.aggregate-earnings.v1");
    expect(stored.status).toBe(ProofStatus.ACTIVE);
    expect(
      decodeProtected(
        (stored.claim as { thresholdEncrypted: string }).thresholdEncrypted,
      ),
    ).toBe("1000.0000000");
  });

  it("never stores or returns component payments or source metadata", async () => {
    const { service } = harness(twoPayments);

    const result = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain("GSOURCE_A");
    expect(serialized).not.toContain("GSOURCE_B");
    expect(serialized).not.toContain("payment_1");
    expect(serialized).not.toContain("op_1");
    expect(serialized).not.toContain("600.0000000");
    expect(serialized).not.toContain(encodeAmount("600.0000000"));
  });

  it("stores a disclosure policy that keeps components hidden", async () => {
    const { service, getStoredProof } = harness(twoPayments);

    await service.createAggregateEarningsProof(user, request() as never);
    const policy = (getStoredProof().claim as { disclosurePolicy: unknown })
      .disclosurePolicy;

    expect(policy).toEqual({
      componentPaymentsHidden: true,
      sourceMetadataHidden: true,
      qualifyingPaymentCount: 2,
      sourceCount: 2,
      aggregationPolicyVersion: "aggregate-earnings-policy.v1",
    });
    expect(JSON.stringify(policy)).not.toContain("GSOURCE");
  });

  it("produces the same aggregate claim regardless of database row order", async () => {
    const forward = harness(twoPayments);
    const reversed = harness([...twoPayments].reverse());

    const first = await forward.service.createAggregateEarningsProof(
      user,
      request() as never,
    );
    const second = await reversed.service.createAggregateEarningsProof(
      user,
      request() as never,
    );

    expect(first.credential.claim).toEqual(second.credential.claim);
    expect(first.credential.privacy).toEqual(second.credential.privacy);
  });

  it("counts a duplicated operation only once", async () => {
    const duplicateOperation: PaymentRow[] = [
      payment({
        id: "payment_a",
        operationId: "shared-operation",
        sourceAddress: "GSOURCE_A",
        amountEncrypted: encodeAmount("100.0000000"),
      }),
      payment({
        id: "payment_b",
        operationId: "shared-operation",
        sourceAddress: "GSOURCE_A",
        amountEncrypted: encodeAmount("100.0000000"),
      }),
    ];
    const { service } = harness(duplicateOperation);

    const result = await service.createAggregateEarningsProof(user, {
      ...request(),
      selectedPaymentIds: ["payment_a", "payment_b"],
    } as never);

    expect(result.credential.claim.totalAmount).toBe("100.0000000");
    expect(result.credential.claim.qualifyingPaymentCount).toBe(1);
  });

  it("rounds component amounts half-up at 7 decimals", async () => {
    const tiny: PaymentRow[] = [
      payment({
        id: "payment_1",
        operationId: "op_1",
        amountEncrypted: encodeAmount("1.99999995"),
      }),
      payment({
        id: "payment_2",
        operationId: "op_2",
        amountEncrypted: encodeAmount("0.00000005"),
      }),
    ];
    const { service } = harness(tiny);

    const result = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );

    expect(result.credential.claim.totalAmount).toBe("2.0000001");
  });

  it("rejects a cross-asset selection", async () => {
    const mixed: PaymentRow[] = [
      twoPayments[0],
      payment({
        id: "payment_2",
        operationId: "op_2",
        assetCode: "XLM",
        assetIssuer: null,
      }),
    ];
    const { service } = harness(mixed);

    await expect(
      service.createAggregateEarningsProof(user, request() as never),
    ).rejects.toThrow(/Cross-asset/);
  });

  it("rejects a period longer than the policy bound", async () => {
    const { service } = harness(twoPayments);

    await expect(
      service.createAggregateEarningsProof(
        user,
        request({
          periodStart: "2025-01-01T00:00:00.000Z",
          periodEnd: "2026-06-01T00:00:00.000Z",
        }) as never,
      ),
    ).rejects.toThrow(/may not exceed/);
  });

  it("rejects an ineligible component", async () => {
    const ineligible: PaymentRow[] = [
      payment({
        id: "payment_1",
        operationId: "op_1",
        classification: PaymentClassification.REIMBURSEMENT,
        isEligible: false,
      }),
      twoPayments[1],
    ];
    const { service } = harness(ineligible);

    await expect(
      service.createAggregateEarningsProof(user, request() as never),
    ).rejects.toThrow(/not an eligible income payment/);
  });

  it("rejects a component outside the requested period", async () => {
    const outside: PaymentRow[] = [
      payment({
        id: "payment_1",
        operationId: "op_1",
        occurredAt: new Date("2024-12-31T00:00:00.000Z"),
      }),
      twoPayments[1],
    ];
    const { service } = harness(outside);

    await expect(
      service.createAggregateEarningsProof(user, request() as never),
    ).rejects.toThrow(/outside the aggregation period/);
  });

  it("rejects selected payments that do not belong to the caller", async () => {
    const { service } = harness([twoPayments[0]]);

    await expect(
      service.createAggregateEarningsProof(user, request() as never),
    ).rejects.toThrow(/One or more selected payments are invalid/);
  });

  it("enqueues an anchoring intent when anchoring is enabled", async () => {
    const { service, createdIntents } = harness(twoPayments, true);

    const result = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );

    expect(createdIntents).toEqual([
      expect.objectContaining({
        operation: "REGISTER",
        status: "PENDING",
      }),
    ]);
    expect(result.anchoring).toEqual({ anchored: false, reason: "pending" });
  });

  it("round-trips through the shared verification pipeline", async () => {
    const { service } = harness(twoPayments);

    const created = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );
    const verification = await service.verifyProof(created.proofId);

    expect(verification.result).toBe(VerificationResult.VALID);
    expect(verification.status).toBe("valid");
    const credential = verification.credential as {
      claim: { totalAmount: string; qualifyingPaymentCount: number };
    };
    expect(credential.claim.totalAmount).toBe("1000.0000000");
    expect(credential.claim.qualifyingPaymentCount).toBe(2);
  });

  it("detects a tampered stored aggregate total", async () => {
    const { service, getStoredProof } = harness(twoPayments);

    const created = await service.createAggregateEarningsProof(
      user,
      request() as never,
    );
    const stored = getStoredProof() as { credentialHash: string };
    stored.credentialHash = "sha256:tampered";

    const verification = await service.verifyProof(created.proofId);

    expect(verification.result).toBe(VerificationResult.INVALID_SIGNATURE);
  });
});
