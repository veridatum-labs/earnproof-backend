import { UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Keypair } from "@stellar/stellar-base";
import { createHash } from "crypto";
import { SessionService } from "./session.service";
import { AuthService } from "./auth.service";

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const keypair = Keypair.random();
const walletAddress = keypair.publicKey();

const challenge = {
  id: "challenge_1",
  walletAddress,
  message: "EarnProof wallet authentication",
  expiresAt: new Date(Date.now() + 60_000),
  usedAt: null,
};

const dbUser = {
  id: "user_1",
  walletAddress,
  walletHash: "sha256:hash",
  role: "WORKER",
};

function makePrismaMock() {
  return {
    walletChallenge: {
      create: jest.fn().mockResolvedValue(challenge),
      findFirst: jest.fn().mockResolvedValue(challenge),
      update: jest.fn().mockResolvedValue({ ...challenge, usedAt: new Date() }),
    },
    user: {
      upsert: jest.fn().mockResolvedValue(dbUser),
      findUnique: jest.fn().mockResolvedValue({
        ...dbUser,
        status: "ACTIVE",
        lastLoginAt: new Date(),
      }),
    },
  };
}

const config = {
  getOrThrow: (key: string) => {
    const values: Record<string, string> = {
      appUrl: "http://localhost:3000",
      "stellar.networkPassphrase": "Test SDF Network ; September 2015",
      sessionSecret: "test_secret_123",
    };
    return values[key];
  },
} as ConfigService;

// ---------------------------------------------------------------------------
// AuthService.createChallenge
// ---------------------------------------------------------------------------

describe("AuthService.createChallenge", () => {
  it("returns a challenge record with id and message", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    await expect(svc.createChallenge(walletAddress)).resolves.toMatchObject({
      id: "challenge_1",
      message: expect.any(String),
    });
  });
});

// ---------------------------------------------------------------------------
// AuthService.verifyChallenge
// ---------------------------------------------------------------------------

describe("AuthService.verifyChallenge", () => {
  it("creates a persisted session and returns tokenType Bearer", async () => {
    const prisma = makePrismaMock();
    // SessionService needs authSession.create
    (prisma as Record<string, unknown>).authSession = {
      create: jest.fn().mockResolvedValue({}),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    const result = await svc.verifyChallenge({
      challengeId: challenge.id,
      walletAddress,
      signature,
    });

    expect(result.user.id).toBe("user_1");
    expect(result.session.tokenType).toBe("Bearer");
    // Token must be opaque format: <id>.<64-hex-chars>
    expect(result.session.token).toMatch(/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/);
    // sessionId and expiresAt must be present in the response
    expect(result.session.sessionId).toBeTruthy();
    expect(result.session.expiresAt).toBeInstanceOf(Date);
  });

  it("rejects raw-message signatures that do not follow SEP-53", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    const signature = keypair
      .sign(Buffer.from(challenge.message, "utf8"))
      .toString("base64");

    await expect(
      svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).rejects.toThrow("Invalid wallet signature");
  });

  it("marks the challenge as used", async () => {
    const prisma = makePrismaMock();
    (prisma as Record<string, unknown>).authSession = {
      create: jest.fn().mockResolvedValue({}),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await svc.verifyChallenge({ challengeId: challenge.id, walletAddress, signature });

    expect(prisma.walletChallenge.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: challenge.id },
        data: { usedAt: expect.any(Date) },
      }),
    );
  });

  it("throws when no matching challenge exists", async () => {
    const prisma = makePrismaMock();
    prisma.walletChallenge.findFirst.mockResolvedValue(null);
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    await expect(
      svc.verifyChallenge({ challengeId: "bad", walletAddress, signature: "sig" }),
    ).rejects.toThrow("Challenge is expired or unavailable");
  });
});

// ---------------------------------------------------------------------------
// AuthService.getSession
// ---------------------------------------------------------------------------

describe("AuthService.getSession", () => {
  it("returns user data for a valid userId", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    await expect(svc.getSession("user_1")).resolves.toMatchObject({
      user: { id: "user_1", walletAddress },
    });
  });

  it("throws UnauthorizedException when user does not exist", async () => {
    const prisma = makePrismaMock();
    prisma.user.findUnique.mockResolvedValue(null);
    const sessionSvc = new SessionService(prisma as never, config);
    const svc = new AuthService(prisma as never, sessionSvc, config);

    await expect(svc.getSession("missing_user")).rejects.toThrow(
      UnauthorizedException,
    );
  });
});

// ---------------------------------------------------------------------------
// AuthService.logout
// ---------------------------------------------------------------------------

describe("AuthService.logout", () => {
  it("calls sessionService.revoke with the supplied sessionId", async () => {
    const prisma = makePrismaMock();
    (prisma as Record<string, unknown>).authSession = {
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const revokeSpy = jest.spyOn(sessionSvc, "revoke").mockResolvedValue();
    const svc = new AuthService(prisma as never, sessionSvc, config);

    await svc.logout("sess_abc");

    expect(revokeSpy).toHaveBeenCalledWith("sess_abc");
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sep53MessageHash(message: string) {
  return createHash("sha256")
    .update("Stellar Signed Message:\n", "utf8")
    .update(message, "utf8")
    .digest();
}
