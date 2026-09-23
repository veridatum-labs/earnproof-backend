import { UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AuthEventType } from "@prisma/client";
import { Keypair } from "@stellar/stellar-base";
import { createHash } from "crypto";
import { AuthService } from "./auth.service";
import { SessionService } from "./session.service";

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
      findUnique: jest.fn().mockResolvedValue(challenge),
      update: jest.fn().mockResolvedValue({ ...challenge, usedAt: new Date() }),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
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

function makeAuditServiceMock() {
  return {
    recordEvent: jest.fn().mockResolvedValue(undefined),
  };
}

function makeRateLimiterMock() {
  return {
    checkChallengeCreationLimit: jest.fn().mockResolvedValue(undefined),
    checkVerificationLimit: jest.fn().mockResolvedValue(undefined),
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
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    await expect(svc.createChallenge(walletAddress)).resolves.toMatchObject({
      id: "challenge_1",
      message: expect.any(String),
    });
  });

  it("checks rate limits before creating challenge", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    await svc.createChallenge(walletAddress, "client-metadata");

    expect(rateLimiter.checkChallengeCreationLimit).toHaveBeenCalledWith(
      walletAddress,
      "client-metadata",
    );
  });

  it("records successful challenge creation", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    await svc.createChallenge(walletAddress);

    expect(auditSvc.recordEvent).toHaveBeenCalledWith(
      AuthEventType.CHALLENGE_CREATED,
      walletAddress,
      {
        challengeId: "challenge_1",
        success: true,
        clientMetadata: undefined,
      },
    );
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
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

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

  it("checks rate limits before verification", async () => {
    const prisma = makePrismaMock();
    (prisma as Record<string, unknown>).authSession = {
      create: jest.fn().mockResolvedValue({}),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await svc.verifyChallenge({
      challengeId: challenge.id,
      walletAddress,
      signature,
      clientMetadata: "client-meta",
    });

    expect(rateLimiter.checkVerificationLimit).toHaveBeenCalledWith(
      walletAddress,
      "client-meta",
    );
  });

  it("records successful verification", async () => {
    const prisma = makePrismaMock();
    (prisma as Record<string, unknown>).authSession = {
      create: jest.fn().mockResolvedValue({}),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await svc.verifyChallenge({
      challengeId: challenge.id,
      walletAddress,
      signature,
    });

    expect(auditSvc.recordEvent).toHaveBeenCalledWith(
      AuthEventType.CHALLENGE_VERIFIED,
      walletAddress,
      {
        challengeId: challenge.id,
        success: true,
        clientMetadata: undefined,
      },
    );
  });

  it("records invalid signature event", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = "invalid_signature";

    await expect(
      svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).rejects.toThrow("Invalid wallet signature");

    expect(auditSvc.recordEvent).toHaveBeenCalledWith(
      AuthEventType.SIGNATURE_INVALID,
      walletAddress,
      {
        challengeId: challenge.id,
        success: false,
        failureReason: "Invalid signature",
        clientMetadata: undefined,
      },
    );
  });

  it("records challenge replay event", async () => {
    const prisma = makePrismaMock();
    // The guarded consume matches nothing, and the challenge turns out to
    // already carry a usedAt: that is a replay, not an expiry.
    // The atomic consumption update matches 0 rows (already used), and the
    // replay-detection lookup finds the challenge with usedAt already set.
    prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 0 });
    prisma.walletChallenge.findFirst.mockResolvedValueOnce({
      ...challenge,
      usedAt: new Date(),
    });

    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await expect(
      svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).rejects.toThrow("Challenge is expired or unavailable");

    expect(auditSvc.recordEvent).toHaveBeenCalledWith(
      AuthEventType.CHALLENGE_REPLAYED,
      walletAddress,
      {
        challengeId: challenge.id,
        success: false,
        failureReason: "Challenge already used",
        clientMetadata: undefined,
      },
    );
  });

  it("records challenge expired event", async () => {
    const prisma = makePrismaMock();
    // Nothing consumed and no used row either: expired, or never existed.
    prisma.walletChallenge.updateMany.mockResolvedValue({ count: 0 });
    prisma.walletChallenge.findFirst.mockResolvedValue(null);
    // The atomic consumption update matches 0 rows (expired/missing), and
    // the replay-detection lookup finds nothing with usedAt set either.
    prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 0 });
    prisma.walletChallenge.findFirst.mockResolvedValueOnce(null);

    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await expect(
      svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).rejects.toThrow("Challenge is expired or unavailable");

    expect(auditSvc.recordEvent).toHaveBeenCalledWith(
      AuthEventType.CHALLENGE_EXPIRED,
      walletAddress,
      {
        challengeId: challenge.id,
        success: false,
        failureReason: "Challenge expired or not found",
        clientMetadata: undefined,
      },
    );
  });

  it("rejects raw-message signatures that do not follow SEP-53", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

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

  it("consumes the challenge atomically before verifying the signature", async () => {
    const prisma = makePrismaMock();
    (prisma as Record<string, unknown>).authSession = {
      create: jest.fn().mockResolvedValue({}),
    };
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await svc.verifyChallenge({ challengeId: challenge.id, walletAddress, signature });

    // Consumed by the guarded update itself, before the signature is checked:
    // the where clause is what makes concurrent verifications race for one row.
    // Consumption happens via the atomic updateMany (usedAt: null in its
    // where clause guards against a concurrent double-consume) — there is
    // no separate .update() call afterward.
    expect(prisma.walletChallenge.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: challenge.id,
          walletAddress,
          usedAt: null,
        }),
        data: { usedAt: expect.any(Date) },
      }),
    );
    expect(prisma.walletChallenge.update).not.toHaveBeenCalled();
  });

  it("throws when no matching challenge exists", async () => {
    const prisma = makePrismaMock();
    prisma.walletChallenge.updateMany.mockResolvedValue({ count: 0 });
    prisma.walletChallenge.findFirst.mockResolvedValue(null);
    prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 0 });
    prisma.walletChallenge.findFirst.mockResolvedValueOnce(null);
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    await expect(
      svc.verifyChallenge({ challengeId: "bad", walletAddress, signature: "sig" }),
    ).rejects.toThrow("Challenge is expired or unavailable");
  });
});

// ---------------------------------------------------------------------------
// Challenge Consumption Regression Tests
// ---------------------------------------------------------------------------

describe("AuthService.verifyChallenge - Challenge Consumption", () => {
  describe("positive: valid unconsumed challenge", () => {
    it("consumes a valid unconsumed challenge successfully and completes auth flow", async () => {
      const prisma = makePrismaMock();
      (prisma as Record<string, unknown>).authSession = {
        create: jest.fn().mockResolvedValue({}),
      };
      const sessionSvc = new SessionService(prisma as never, config);
      const auditSvc = makeAuditServiceMock();
      const rateLimiter = makeRateLimiterMock();
      const svc = new AuthService(
        prisma as never,
        sessionSvc,
        auditSvc as never,
        rateLimiter as never,
        config,
      );

      const signature = keypair
        .sign(sep53MessageHash(challenge.message))
        .toString("base64");

      const result = await svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      });

      // Verify the auth flow completed successfully
      expect(result.user).toBeDefined();
      expect(result.session).toBeDefined();
      expect(result.session.token).toBeTruthy();
      expect(result.session.sessionId).toBeTruthy();

      // Verify the challenge was atomically consumed before verification
      expect(prisma.walletChallenge.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            id: challenge.id,
            walletAddress,
            usedAt: null, // Guard: only consume if not yet used
            expiresAt: { gt: expect.any(Date) },
          }),
          data: { usedAt: expect.any(Date) },
        }),
      );

      // Verify success was audited
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.CHALLENGE_VERIFIED,
        walletAddress,
        expect.objectContaining({
          challengeId: challenge.id,
          success: true,
        }),
      );
    });
  });

  describe("negative: already-consumed challenge rejection", () => {
    it("rejects an already-consumed challenge cleanly without silent no-op", async () => {
      const prisma = makePrismaMock();
      // Simulate: atomic update matches 0 rows (challenge already consumed)
      prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 0 });
      // Replay detection finds the challenge was already used
      prisma.walletChallenge.findFirst.mockResolvedValueOnce({
        ...challenge,
        usedAt: new Date(Date.now() - 30_000), // Used 30 seconds ago
      });

      const sessionSvc = new SessionService(prisma as never, config);
      const auditSvc = makeAuditServiceMock();
      const rateLimiter = makeRateLimiterMock();
      const svc = new AuthService(
        prisma as never,
        sessionSvc,
        auditSvc as never,
        rateLimiter as never,
        config,
      );

      const signature = keypair
        .sign(sep53MessageHash(challenge.message))
        .toString("base64");

      // Should throw UnauthorizedException, not silently allow auth
      await expect(
        svc.verifyChallenge({
          challengeId: challenge.id,
          walletAddress,
          signature,
        }),
      ).rejects.toThrow(UnauthorizedException);

      // Verify replay was detected and audited
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.CHALLENGE_REPLAYED,
        walletAddress,
        expect.objectContaining({
          challengeId: challenge.id,
          success: false,
          failureReason: "Challenge already used",
        }),
      );

      // Verify no session was created
      expect((prisma as Record<string, unknown>).user?.upsert).not.toHaveBeenCalled();
    });
  });

  describe("boundary: concurrent consumption attempts", () => {
    it("ensures only one of two concurrent consumption attempts succeeds", async () => {
      // This test simulates the race condition at the database level.
      // Both requests call updateMany with the same guarded where-clause.
      // Only one will match (because usedAt: null in the guard prevents both from matching).

      const prisma = makePrismaMock();
      (prisma as Record<string, unknown>).authSession = {
        create: jest.fn().mockResolvedValue({}),
      };

      // Request A: succeeds in consuming (count: 1)
      // Request B: fails to consume because challenge is already used (count: 0)
      let callCount = 0;
      prisma.walletChallenge.updateMany.mockImplementation(async () => {
        callCount++;
        if (callCount === 1) {
          // First call (Request A) succeeds
          return { count: 1 };
        } else {
          // Second call (Request B) fails
          return { count: 0 };
        }
      });

      // Request B's replay detection finds the challenge was already used
      prisma.walletChallenge.findFirst.mockResolvedValueOnce({
        ...challenge,
        usedAt: new Date(),
      });

      const sessionSvc = new SessionService(prisma as never, config);
      const auditSvc = makeAuditServiceMock();
      const rateLimiter = makeRateLimiterMock();
      const svc = new AuthService(
        prisma as never,
        sessionSvc,
        auditSvc as never,
        rateLimiter as never,
        config,
      );

      const signature = keypair
        .sign(sep53MessageHash(challenge.message))
        .toString("base64");

      // Request A should succeed
      const resultA = await svc.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      });

      expect(resultA.user).toBeDefined();
      expect(resultA.session.token).toBeTruthy();

      // Request B should fail with replay error
      await expect(
        svc.verifyChallenge({
          challengeId: challenge.id,
          walletAddress,
          signature,
        }),
      ).rejects.toThrow(UnauthorizedException);

      // Verify that updateMany was called twice (both attempts tried to consume)
      expect(prisma.walletChallenge.updateMany).toHaveBeenCalledTimes(2);

      // Verify that only Request A's success was audited
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.CHALLENGE_VERIFIED,
        walletAddress,
        expect.objectContaining({ success: true }),
      );

      // Verify that Request B's replay was audited
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.CHALLENGE_REPLAYED,
        walletAddress,
        expect.objectContaining({
          success: false,
          failureReason: "Challenge already used",
        }),
      );
    });

    it("prevents signature oracle attacks by consuming challenge before verification", async () => {
      const prisma = makePrismaMock();
      // Challenge is consumed (updateMany succeeds)
      prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 1 });

      const sessionSvc = new SessionService(prisma as never, config);
      const auditSvc = makeAuditServiceMock();
      const rateLimiter = makeRateLimiterMock();
      const svc = new AuthService(
        prisma as never,
        sessionSvc,
        auditSvc as never,
        rateLimiter as never,
        config,
      );

      // Attempt with an invalid signature
      const invalidSignature = "invalid_sig_attempt_1";

      await expect(
        svc.verifyChallenge({
          challengeId: challenge.id,
          walletAddress,
          signature: invalidSignature,
        }),
      ).rejects.toThrow("Invalid wallet signature");

      // Even though the signature is invalid, the challenge should have been consumed
      // (so a second attempt with a different invalid signature should fail as replay, not signature invalid)
      expect(prisma.walletChallenge.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: { usedAt: expect.any(Date) },
        }),
      );

      // Verify signature failure was audited
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.SIGNATURE_INVALID,
        walletAddress,
        expect.objectContaining({
          success: false,
          failureReason: "Invalid signature",
        }),
      );

      // A second attempt would be blocked by the consumed state
      prisma.walletChallenge.updateMany.mockResolvedValueOnce({ count: 0 });
      prisma.walletChallenge.findFirst.mockResolvedValueOnce({
        ...challenge,
        usedAt: new Date(), // Already consumed
      });

      const invalidSignature2 = "invalid_sig_attempt_2";

      await expect(
        svc.verifyChallenge({
          challengeId: challenge.id,
          walletAddress,
          signature: invalidSignature2,
        }),
      ).rejects.toThrow("Challenge is expired or unavailable");

      // Second attempt should be audited as replay
      expect(auditSvc.recordEvent).toHaveBeenCalledWith(
        AuthEventType.CHALLENGE_REPLAYED,
        walletAddress,
        expect.objectContaining({
          success: false,
          failureReason: "Challenge already used",
        }),
      );
    });
  });
});

// ---------------------------------------------------------------------------
// AuthService.getSession
// ---------------------------------------------------------------------------

describe("AuthService.getSession", () => {
  it("returns user data for a valid userId", async () => {
    const prisma = makePrismaMock();
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

    await expect(svc.getSession("user_1")).resolves.toMatchObject({
      user: { id: "user_1", walletAddress },
    });
  });

  it("throws UnauthorizedException when user does not exist", async () => {
    const prisma = makePrismaMock();
    prisma.user.findUnique.mockResolvedValue(null);
    const sessionSvc = new SessionService(prisma as never, config);
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

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
    const auditSvc = makeAuditServiceMock();
    const rateLimiter = makeRateLimiterMock();
    const svc = new AuthService(
      prisma as never,
      sessionSvc,
      auditSvc as never,
      rateLimiter as never,
      config,
    );

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
