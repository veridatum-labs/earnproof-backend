import { UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { SessionService } from "./session.service";

// ---------------------------------------------------------------------------
// Minimal Prisma mock — every method is a jest.fn() returning sensible defaults
// ---------------------------------------------------------------------------
function makePrismaMock() {
  return {
    authSession: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    $transaction: jest.fn(),
  };
}

const config = {
  getOrThrow: () => "test_secret_xyz",
} as unknown as ConfigService;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a valid-looking active session row. */
function activeSession(overrides: Partial<{
  id: string;
  userId: string;
  tokenHash: string;
  revokedAt: Date | null;
  expiresAt: Date;
}> = {}) {
  return {
    id: overrides.id ?? "sess_1",
    userId: overrides.userId ?? "user_1",
    tokenHash: overrides.tokenHash ?? "hash",
    revokedAt: overrides.revokedAt ?? null,
    expiresAt: overrides.expiresAt ?? new Date(Date.now() + 60_000),
  };
}

// ---------------------------------------------------------------------------
// SessionService.create
// ---------------------------------------------------------------------------

describe("SessionService.create", () => {
  it("returns an opaque token, sessionId and expiresAt", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.create.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    const result = await svc.create({
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });

    expect(result.token).toMatch(/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/);
    expect(result.sessionId).toBeTruthy();
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("stores only the hash — the raw token is never written to DB", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.create.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    const { token } = await svc.create({
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });

    const [call] = prisma.authSession.create.mock.calls;
    const storedData = call[0].data as Record<string, unknown>;

    // The raw token must not appear anywhere in the stored data.
    expect(JSON.stringify(storedData)).not.toContain(token);
    // tokenHash must be present and must differ from the token.
    expect(storedData.tokenHash).toBeTruthy();
    expect(storedData.tokenHash).not.toEqual(token);
  });

  it("uses the supplied ttl", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.create.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);
    const before = Date.now();

    const { expiresAt } = await svc.create(
      { id: "u", walletAddress: "G".padEnd(56, "A"), walletHash: "h", role: "WORKER" },
      3600,
    );

    const diff = expiresAt.getTime() - before;
    expect(diff).toBeGreaterThanOrEqual(3600 * 1000 - 50);
    expect(diff).toBeLessThanOrEqual(3600 * 1000 + 500);
  });
});

// ---------------------------------------------------------------------------
// SessionService.validate
// ---------------------------------------------------------------------------

describe("SessionService.validate", () => {
  it("returns sessionId and userId for a valid token", async () => {
    const prisma = makePrismaMock();
    const sess = activeSession();
    prisma.authSession.findUnique.mockResolvedValue(sess);
    prisma.authSession.update.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    // Create a real token so the format check passes.
    prisma.authSession.create.mockResolvedValue({});
    const { token } = await svc.create({
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });

    // Re-wire findUnique to return our fake session for whatever hash is queried.
    prisma.authSession.findUnique.mockResolvedValue(sess);
    const result = await svc.validate(token);

    expect(result.userId).toBe("user_1");
    expect(result.sessionId).toBe("sess_1");
  });

  it("rejects a malformed token (no dot separator)", async () => {
    const prisma = makePrismaMock();
    const svc = new SessionService(prisma as never, config);

    await expect(svc.validate("nodottoken")).rejects.toThrow(
      UnauthorizedException,
    );
    expect(prisma.authSession.findUnique).not.toHaveBeenCalled();
  });

  it("rejects an empty string token", async () => {
    const prisma = makePrismaMock();
    const svc = new SessionService(prisma as never, config);

    await expect(svc.validate("")).rejects.toThrow(UnauthorizedException);
  });

  it("rejects a token whose session row is missing", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(null);
    const svc = new SessionService(prisma as never, config);

    await expect(svc.validate("sid.a".padEnd(67, "b"))).rejects.toThrow(
      "Session not found",
    );
  });

  it("rejects a revoked session", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(
      activeSession({ revokedAt: new Date() }),
    );
    const svc = new SessionService(prisma as never, config);

    await expect(svc.validate("sid.abc123def456".padEnd(67, "0"))).rejects.toThrow(
      "Session has been revoked",
    );
  });

  it("rejects an expired session", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(
      activeSession({ expiresAt: new Date(Date.now() - 1000) }),
    );
    const svc = new SessionService(prisma as never, config);

    await expect(svc.validate("sid.abc123def456".padEnd(67, "0"))).rejects.toThrow(
      "Session has expired",
    );
  });

  it("updates lastUsedAt on successful validation", async () => {
    const prisma = makePrismaMock();
    const sess = activeSession();
    prisma.authSession.findUnique.mockResolvedValue(sess);
    prisma.authSession.update.mockResolvedValue({});
    prisma.authSession.create.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    const { token } = await svc.create({
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });
    prisma.authSession.findUnique.mockResolvedValue(sess);

    await svc.validate(token);

    // Give the fire-and-forget update a tick to fire.
    await new Promise((r) => setImmediate(r));
    expect(prisma.authSession.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: sess.id },
        data: expect.objectContaining({ lastUsedAt: expect.any(Date) }),
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// SessionService.revoke
// ---------------------------------------------------------------------------

describe("SessionService.revoke", () => {
  it("sets revokedAt on the targeted session", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.updateMany.mockResolvedValue({ count: 1 });
    const svc = new SessionService(prisma as never, config);

    await svc.revoke("sess_1");

    expect(prisma.authSession.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ id: "sess_1", revokedAt: null }),
        data: expect.objectContaining({ revokedAt: expect.any(Date) }),
      }),
    );
  });

  it("is idempotent — revoking twice does not throw", async () => {
    const prisma = makePrismaMock();
    // Second call matches 0 rows — still resolves cleanly.
    prisma.authSession.updateMany
      .mockResolvedValueOnce({ count: 1 })
      .mockResolvedValueOnce({ count: 0 });
    const svc = new SessionService(prisma as never, config);

    await expect(svc.revoke("sess_1")).resolves.toBeUndefined();
    await expect(svc.revoke("sess_1")).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SessionService.rotate
// ---------------------------------------------------------------------------

describe("SessionService.rotate", () => {
  it("creates a new session and revokes the old one atomically", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(
      activeSession({ id: "old_sess" }),
    );
    prisma.$transaction.mockImplementation(async (ops: Promise<unknown>[]) => {
      await Promise.all(ops);
    });
    prisma.authSession.create.mockResolvedValue({});
    prisma.authSession.update.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    const result = await svc.rotate("old_sess", {
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });

    expect(result.token).toMatch(/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/);
    expect(result.sessionId).not.toBe("old_sess");
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // The transaction must have been called.
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);

    // The old session must have been revoked inside the transaction.
    const [[createOp, updateOp]] = prisma.$transaction.mock.calls as [
      [Promise<unknown>, Promise<unknown>][],
    ];
    // We can't easily inspect the promise args directly, but confirm that
    // both create and update were invoked (one for new, one to revoke old).
    void createOp;
    void updateOp;
    expect(prisma.authSession.create).toHaveBeenCalledTimes(1);
    expect(prisma.authSession.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "old_sess" },
        data: expect.objectContaining({ revokedAt: expect.any(Date) }),
      }),
    );
  });

  it("rejects rotation of an already-revoked session", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(
      activeSession({ id: "old_sess", revokedAt: new Date() }),
    );
    const svc = new SessionService(prisma as never, config);

    await expect(
      svc.rotate("old_sess", {
        id: "user_1",
        walletAddress: "G".padEnd(56, "A"),
        walletHash: "sha256:abc",
        role: "WORKER",
      }),
    ).rejects.toThrow("Cannot rotate an already-revoked session");
  });

  it("rejects rotation of a missing session", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.findUnique.mockResolvedValue(null);
    const svc = new SessionService(prisma as never, config);

    await expect(
      svc.rotate("ghost_sess", {
        id: "user_1",
        walletAddress: "G".padEnd(56, "A"),
        walletHash: "sha256:abc",
        role: "WORKER",
      }),
    ).rejects.toThrow("Session not found");
  });

  it("issues a token that is different from the original", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.create.mockResolvedValue({});
    prisma.authSession.findUnique.mockResolvedValue(
      activeSession({ id: "old_sess" }),
    );
    prisma.$transaction.mockImplementation(async (ops: Promise<unknown>[]) => {
      await Promise.all(ops);
    });
    prisma.authSession.update.mockResolvedValue({});
    const svc = new SessionService(prisma as never, config);

    const originalToken = "old_sess.aaaa".padEnd(67, "0");
    const rotated = await svc.rotate("old_sess", {
      id: "user_1",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:abc",
      role: "WORKER",
    });

    expect(rotated.token).not.toBe(originalToken);
  });
});

// ---------------------------------------------------------------------------
// SessionService.revokeAll
// ---------------------------------------------------------------------------

describe("SessionService.revokeAll", () => {
  it("revokes all active sessions for a user", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.updateMany.mockResolvedValue({ count: 3 });
    const svc = new SessionService(prisma as never, config);

    await svc.revokeAll("user_1");

    expect(prisma.authSession.updateMany).toHaveBeenCalledWith({
      where: { userId: "user_1", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });
});

// ---------------------------------------------------------------------------
// SessionService.deleteExpired  (retention/cleanup)
// ---------------------------------------------------------------------------

describe("SessionService.deleteExpired", () => {
  it("deletes rows with expiresAt before the cutoff and returns count", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.deleteMany.mockResolvedValue({ count: 7 });
    const svc = new SessionService(prisma as never, config);

    const count = await svc.deleteExpired(new Date("2030-01-01"));

    expect(count).toBe(7);
    expect(prisma.authSession.deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { lt: new Date("2030-01-01") } },
    });
  });

  it("defaults cutoff to now when no argument is provided", async () => {
    const prisma = makePrismaMock();
    prisma.authSession.deleteMany.mockResolvedValue({ count: 0 });
    const svc = new SessionService(prisma as never, config);
    const before = new Date();

    await svc.deleteExpired();

    const [[call]] = prisma.authSession.deleteMany.mock.calls as [
      [{ where: { expiresAt: { lt: Date } } }][],
    ];
    const cutoff = call.where.expiresAt.lt;
    expect(cutoff.getTime()).toBeGreaterThanOrEqual(before.getTime() - 10);
    expect(cutoff.getTime()).toBeLessThanOrEqual(Date.now() + 10);
  });
});

// ---------------------------------------------------------------------------
// Concurrent revocation — simulates a race between two logout requests
// ---------------------------------------------------------------------------

describe("SessionService concurrent revocation", () => {
  it("handles two simultaneous revocations without throwing", async () => {
    const prisma = makePrismaMock();
    // First call revokes (count: 1), second is a no-op (count: 0).
    prisma.authSession.updateMany
      .mockResolvedValueOnce({ count: 1 })
      .mockResolvedValueOnce({ count: 0 });
    const svc = new SessionService(prisma as never, config);

    const [r1, r2] = await Promise.allSettled([
      svc.revoke("sess_1"),
      svc.revoke("sess_1"),
    ]);

    expect(r1.status).toBe("fulfilled");
    expect(r2.status).toBe("fulfilled");
  });
});
