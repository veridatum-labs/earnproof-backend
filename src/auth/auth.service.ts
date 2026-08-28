import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AuthEventType } from "@prisma/client";
import { Keypair, StrKey } from "@stellar/stellar-base";
import { createHash, randomBytes } from "crypto";
import { PrismaService } from "../database/prisma.service";
import { sha256 } from "../common/crypto/hash";
import { AuthAuditService } from "./auth-audit.service";
import { AuthRateLimiterService } from "./auth-rate-limiter.service";
import { SessionService } from "./session.service";

@Injectable()
export class AuthService {
  private readonly appUrl: string;
  private readonly networkPassphrase: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessionService: SessionService,
    private readonly auditService: AuthAuditService,
    private readonly rateLimiter: AuthRateLimiterService,
    configService: ConfigService,
  ) {
    this.appUrl = configService.getOrThrow<string>("appUrl");
    this.networkPassphrase = configService.getOrThrow<string>(
      "stellar.networkPassphrase",
    );
  }

  async createChallenge(walletAddress: string, clientMetadata?: string) {
    this.assertValidPublicKey(walletAddress);

    // Check rate limits before creating challenge
    await this.rateLimiter.checkChallengeCreationLimit(
      walletAddress,
      clientMetadata,
    );

    const nonce = randomBytes(24).toString("base64url");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const message = [
      "EarnProof wallet authentication",
      `Domain: ${this.appUrl}`,
      `Network: ${this.networkPassphrase}`,
      `Wallet: ${walletAddress}`,
      `Nonce: ${nonce}`,
      `Expires At: ${expiresAt.toISOString()}`,
    ].join("\n");

    const challenge = await this.prisma.walletChallenge.create({
      data: {
        walletAddress,
        nonceHash: sha256(nonce),
        message,
        expiresAt,
      },
      select: {
        id: true,
        message: true,
        expiresAt: true,
      },
    });

    // Record successful challenge creation
    await this.auditService.recordEvent(
      AuthEventType.CHALLENGE_CREATED,
      walletAddress,
      {
        challengeId: challenge.id,
        success: true,
        clientMetadata,
      },
    );

    return challenge;
  }

  async verifyChallenge(input: {
    challengeId: string;
    walletAddress: string;
    signature: string;
    clientMetadata?: string;
  }) {
    this.assertValidPublicKey(input.walletAddress);

    // Check rate limits before verification attempt
    await this.rateLimiter.checkVerificationLimit(
      input.walletAddress,
      input.clientMetadata,
    );

    const challenge = await this.prisma.walletChallenge.findFirst({
      where: {
        id: input.challengeId,
        walletAddress: input.walletAddress,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
    });

    if (!challenge) {
      // Determine if challenge was used (replay) or expired
      const usedChallenge = await this.prisma.walletChallenge.findFirst({
        where: {
          id: input.challengeId,
          walletAddress: input.walletAddress,
          usedAt: { not: null },
        },
      });

      if (usedChallenge) {
        await this.auditService.recordEvent(
          AuthEventType.CHALLENGE_REPLAYED,
          input.walletAddress,
          {
            challengeId: input.challengeId,
            success: false,
            failureReason: "Challenge already used",
            clientMetadata: input.clientMetadata,
          },
        );
      } else {
        await this.auditService.recordEvent(
          AuthEventType.CHALLENGE_EXPIRED,
          input.walletAddress,
          {
            challengeId: input.challengeId,
            success: false,
            failureReason: "Challenge expired or not found",
            clientMetadata: input.clientMetadata,
          },
        );
      }

      throw new UnauthorizedException("Challenge is expired or unavailable");
    }

    const isValid = this.verifySignature(
      input.walletAddress,
      challenge.message,
      input.signature,
    );

    if (!isValid) {
      await this.auditService.recordEvent(
        AuthEventType.SIGNATURE_INVALID,
        input.walletAddress,
        {
          challengeId: input.challengeId,
          success: false,
          failureReason: "Invalid signature",
          clientMetadata: input.clientMetadata,
        },
      );

      throw new UnauthorizedException("Invalid wallet signature");
    }

    const walletHash = `sha256:${sha256(input.walletAddress)}`;
    const user = await this.prisma.user.upsert({
      where: { walletAddress: input.walletAddress },
      update: { walletHash, lastLoginAt: new Date() },
      create: {
        walletAddress: input.walletAddress,
        walletHash,
        lastLoginAt: new Date(),
      },
    });

    // Mark challenge as consumed before issuing a session so that a crash
    // between the two writes leaves no valid challenge open.
    await this.prisma.walletChallenge.update({
      where: { id: challenge.id },
      data: { usedAt: new Date() },
    });

    // Create a persisted, revocable session.  Only the hash is stored.
    const { token, sessionId, expiresAt } = await this.sessionService.create({
      id: user.id,
      walletAddress: user.walletAddress,
      walletHash: user.walletHash,
      role: user.role,
    });

    // Record successful verification
    await this.auditService.recordEvent(
      AuthEventType.CHALLENGE_VERIFIED,
      input.walletAddress,
      {
        challengeId: input.challengeId,
        success: true,
        clientMetadata: input.clientMetadata,
      },
    );

    return {
      user: {
        id: user.id,
        walletAddress: user.walletAddress,
        walletHash: user.walletHash,
        role: user.role,
      },
      session: {
        token,
        tokenType: "Bearer",
        sessionId,
        expiresAt,
      },
    };
  }

  async getSession(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        walletAddress: true,
        walletHash: true,
        role: true,
        status: true,
        lastLoginAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException("User session is no longer valid");
    }

    return { user };
  }

  /**
   * Revoke the caller's active session server-side.
   * The sessionId is extracted from the authenticated request context by
   * the controller — the raw token is never passed here.
   */
  async logout(sessionId: string): Promise<void> {
    await this.sessionService.revoke(sessionId);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private verifySignature(
    walletAddress: string,
    message: string,
    signature: string,
  ) {
    const signatureBuffer = this.decodeSignature(signature);
    return Keypair.fromPublicKey(walletAddress).verify(
      this.sep53MessageHash(message),
      signatureBuffer,
    );
  }

  private sep53MessageHash(message: string) {
    return createHash("sha256")
      .update("Stellar Signed Message:\n", "utf8")
      .update(message, "utf8")
      .digest();
  }

  private decodeSignature(signature: string) {
    if (/^[a-f0-9]+$/i.test(signature) && signature.length % 2 === 0) {
      return Buffer.from(signature, "hex");
    }
    return Buffer.from(signature, "base64");
  }

  private assertValidPublicKey(walletAddress: string) {
    if (!StrKey.isValidEd25519PublicKey(walletAddress)) {
      throw new BadRequestException("Invalid Stellar public key");
    }
  }
}
