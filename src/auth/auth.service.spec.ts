import { ConfigService } from "@nestjs/config";
import { Keypair } from "@stellar/stellar-base";
import { createHash } from "crypto";
import { AuthTokenService } from "./auth-token.service";
import { AuthService } from "./auth.service";

describe("AuthService", () => {
  const keypair = Keypair.random();
  const walletAddress = keypair.publicKey();
  const challenge = {
    id: "challenge_1",
    walletAddress,
    message: "EarnProof wallet authentication",
    expiresAt: new Date(Date.now() + 60_000),
    usedAt: null,
  };

  const prisma = {
    walletChallenge: {
      create: jest.fn().mockResolvedValue(challenge),
      findFirst: jest.fn().mockResolvedValue(challenge),
      findUnique: jest.fn().mockResolvedValue(challenge),
      update: jest.fn().mockResolvedValue({ ...challenge, usedAt: new Date() }),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    user: {
      upsert: jest.fn().mockResolvedValue({
        id: "user_1",
        walletAddress,
        walletHash: "sha256:hash",
        role: "WORKER",
      }),
      findUnique: jest.fn(),
    },
  };

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

  const service = new AuthService(
    prisma as never,
    new AuthTokenService(config),
    config,
  );

  it("creates wallet challenges", async () => {
    await expect(service.createChallenge(walletAddress)).resolves.toMatchObject({
      id: "challenge_1",
      walletAddress,
    });
  });

  it("verifies SEP-53 signatures and returns bearer session", async () => {
    const signature = keypair
      .sign(sep53MessageHash(challenge.message))
      .toString("base64");

    await expect(
      service.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).resolves.toMatchObject({
      user: {
        id: "user_1",
        walletAddress,
      },
      session: {
        tokenType: "Bearer",
      },
    });
  });

  it("rejects raw-message signatures that do not follow SEP-53", async () => {
    const signature = keypair
      .sign(Buffer.from(challenge.message, "utf8"))
      .toString("base64");

    await expect(
      service.verifyChallenge({
        challengeId: challenge.id,
        walletAddress,
        signature,
      }),
    ).rejects.toThrow("Invalid wallet signature");
  });
});

function sep53MessageHash(message: string) {
  return createHash("sha256")
    .update("Stellar Signed Message:\n", "utf8")
    .update(message, "utf8")
    .digest();
}
