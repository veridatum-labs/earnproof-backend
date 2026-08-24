import { AnchoringOperation, AnchoringStatus } from "@prisma/client";
import { AnchoringWorkerService } from "./anchoring-worker.service";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(enabled = true) {
  return {
    get: jest.fn((key: string) => {
      if (key === "contractAnchoring.enabled") return enabled;
      return undefined;
    }),
  };
}

function makeIntent(overrides: Record<string, unknown> = {}) {
  return {
    id: "intent_1",
    proofId: "proof_1",
    operation: AnchoringOperation.REGISTER,
    status: AnchoringStatus.PENDING,
    attemptCount: 0,
    lastAttemptAt: null,
    nextRetryAt: null,
    transactionHash: null,
    ledger: null,
    lastErrorSafe: null,
    permanentError: false,
    proof: { commitment: "sha256:abc", expiresAt: new Date("2027-01-01") },
    ...overrides,
  };
}

function makeAnchoring(result: unknown = { anchored: true, transactionHash: "tx_1" }) {
  return {
    anchorProof: jest.fn().mockResolvedValue(result),
    revokeProof: jest.fn().mockResolvedValue(result),
  };
}

function makePrisma(intentOverrides?: Record<string, unknown>) {
  const intent = makeIntent(intentOverrides);
  return {
    anchoringIntent: {
      findUnique: jest.fn().mockResolvedValue(intent),
      findFirst: jest.fn().mockResolvedValue(null),
      update: jest.fn().mockResolvedValue(intent),
      updateMany: jest.fn().mockResolvedValue({ count: 0 }),
      findMany: jest.fn().mockResolvedValue([intent]),
      create: jest.fn().mockResolvedValue(intent),
    },
    proof: {
      update: jest.fn().mockResolvedValue({ id: "proof_1" }),
    },
    $transaction: jest.fn().mockImplementation(async (arg) => {
      if (typeof arg === "function") {
        return arg({
          anchoringIntent: {
            findMany: jest.fn().mockResolvedValue([intent]),
            updateMany: jest.fn().mockResolvedValue({ count: 1 }),
            findFirst: jest.fn().mockResolvedValue(null),
            update: jest.fn().mockResolvedValue(intent),
          },
        });
      }
      // array form
      return Promise.all(arg.map((p: Promise<unknown>) => p));
    }),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AnchoringWorkerService", () => {
  describe("processIntent", () => {
    it("confirms a REGISTER intent and updates proof.contractTransactionHash", async () => {
      const prisma = makePrisma();
      const anchoring = makeAnchoring({ anchored: true, transactionHash: "tx_abc" });
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(anchoring.anchorProof).toHaveBeenCalledWith(
        expect.objectContaining({ proofId: "proof_1" }),
      );
      // Both intent update and proof update must be issued atomically via $transaction.
      expect(prisma.$transaction).toHaveBeenCalled();
    });

    it("is idempotent — skips CLI call when a CONFIRMED intent already exists for (proofId, operation)", async () => {
      const prisma = makePrisma();
      // Simulate an already-confirmed intent for the same (proofId, operation).
      prisma.anchoringIntent.findFirst = jest.fn().mockResolvedValue({
        transactionHash: "tx_existing",
        ledger: "1234",
      });
      const anchoring = makeAnchoring();
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(anchoring.anchorProof).not.toHaveBeenCalled();
      expect(prisma.anchoringIntent.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: AnchoringStatus.CONFIRMED }),
        }),
      );
    });

    it("skips terminal intents — CONFIRMED intent is a no-op (duplicate delivery)", async () => {
      const prisma = makePrisma({ status: AnchoringStatus.CONFIRMED });
      const anchoring = makeAnchoring();
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      // Already terminal: no CLI call, no DB write.
      expect(anchoring.anchorProof).not.toHaveBeenCalled();
      expect(prisma.anchoringIntent.update).not.toHaveBeenCalled();
    });

    it("skips terminal intents — FAILED intent is a no-op (duplicate delivery)", async () => {
      const prisma = makePrisma({ status: AnchoringStatus.FAILED });
      const anchoring = makeAnchoring();
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(anchoring.anchorProof).not.toHaveBeenCalled();
      expect(prisma.anchoringIntent.update).not.toHaveBeenCalled();
    });

    it("retries transient failures with backoff and does NOT mark permanent", async () => {
      const prisma = makePrisma();
      const anchoring = {
        anchorProof: jest.fn().mockRejectedValue(new Error("connection timeout")),
        revokeProof: jest.fn(),
      };
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(prisma.anchoringIntent.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: AnchoringStatus.PENDING,
            permanentError: false,
            nextRetryAt: expect.any(Date),
            lastErrorSafe: expect.stringContaining("timeout"),
          }),
        }),
      );
    });

    it("marks an intent permanently failed when error matches a permanent pattern", async () => {
      const prisma = makePrisma();
      const anchoring = {
        anchorProof: jest.fn().mockRejectedValue(new Error("proof already registered")),
        revokeProof: jest.fn(),
      };
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(prisma.anchoringIntent.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: AnchoringStatus.FAILED,
            permanentError: true,
          }),
        }),
      );
    });

    it("marks an intent permanently failed when MAX_ATTEMPTS is reached", async () => {
      // Simulate attemptCount already at 9 (one below max 10).
      const prisma = makePrisma({ attemptCount: 9 });
      const anchoring = {
        anchorProof: jest.fn().mockRejectedValue(new Error("network error")),
        revokeProof: jest.fn(),
      };
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(prisma.anchoringIntent.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            status: AnchoringStatus.FAILED,
            permanentError: true,
          }),
        }),
      );
    });

    it("does NOT store secrets in lastErrorSafe when error contains a Stellar secret key pattern", async () => {
      const secretKey = `S${"A".repeat(55)}`; // 56-char S-prefixed key
      const prisma = makePrisma();
      const anchoring = {
        anchorProof: jest
          .fn()
          .mockRejectedValue(new Error(`failed with key ${secretKey}`)),
        revokeProof: jest.fn(),
      };
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      const updateCall = (prisma.anchoringIntent.update as jest.Mock).mock.calls[0][0];
      expect(updateCall.data.lastErrorSafe).not.toContain(secretKey);
      expect(updateCall.data.lastErrorSafe).toContain("[REDACTED_SECRET]");
    });

    it("does NOT store env-var-like credentials in lastErrorSafe", async () => {
      const prisma = makePrisma();
      const anchoring = {
        anchorProof: jest
          .fn()
          .mockRejectedValue(
            new Error("failed: STELLAR_CLI_SOURCE=SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
          ),
        revokeProof: jest.fn(),
      };
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      const updateCall = (prisma.anchoringIntent.update as jest.Mock).mock.calls[0][0];
      expect(updateCall.data.lastErrorSafe).not.toContain("STELLAR_CLI_SOURCE=");
    });
  });

  describe("poll — crash recovery", () => {
    it("resets stale PROCESSING intents back to PENDING", async () => {
      const prisma = makePrisma();
      // Override to simulate stale PROCESSING reset finds 2 records.
      prisma.anchoringIntent.updateMany = jest.fn().mockResolvedValue({ count: 2 });
      // processBatch claims nothing.
      prisma.$transaction = jest.fn().mockResolvedValue([]);

      const worker = new AnchoringWorkerService(
        prisma as never,
        makeAnchoring() as never,
        makeConfig() as never,
      );

      await worker.poll();

      expect(prisma.anchoringIntent.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ status: AnchoringStatus.PROCESSING }),
          data: expect.objectContaining({ status: AnchoringStatus.PENDING }),
        }),
      );
    });

    it("does not poll when anchoring is disabled", async () => {
      const prisma = makePrisma();
      const worker = new AnchoringWorkerService(
        prisma as never,
        makeAnchoring() as never,
        makeConfig(false) as never,
      );

      await worker.poll();

      expect(prisma.anchoringIntent.updateMany).not.toHaveBeenCalled();
    });
  });

  describe("REVOKE operation", () => {
    it("calls revokeProof for REVOKE intents", async () => {
      const prisma = makePrisma({ operation: AnchoringOperation.REVOKE });
      const anchoring = makeAnchoring({ anchored: true, transactionHash: "tx_revoke" });
      const worker = new AnchoringWorkerService(
        prisma as never,
        anchoring as never,
        makeConfig() as never,
      );

      await worker.processIntent("intent_1");

      expect(anchoring.revokeProof).toHaveBeenCalledWith("proof_1");
      expect(anchoring.anchorProof).not.toHaveBeenCalled();
    });
  });
});
