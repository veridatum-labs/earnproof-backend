import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Keypair, StrKey } from "@stellar/stellar-base";
import { createHash, randomBytes } from "crypto";
import { PrismaService } from "../database/prisma.service";
import { sha256 } from "../common/crypto/hash";
import { AuthTokenService } from "./auth-token.service";

@Injectable()
export class AuthService {
  private readonly appUrl: string;
  private readonly networkPassphrase: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly authTokenService: AuthTokenService,
    configService: ConfigService,
  ) {
    this.appUrl = configService.getOrThrow<string>("appUrl");
    this.networkPassphrase = configService.getOrThrow<string>(
      "stellar.networkPassphrase",
    );
  }

  async createChallenge(walletAddress: string) {
    this.assertValidPublicKey(walletAddress);

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

    return challenge;
  }

  async verifyChallenge(input: {
    challengeId: string;
    walletAddress: string;
    signature: string;
  }) {
    this.assertValidPublicKey(input.walletAddress);

    // Atomically mark challenge as consumed only if it exists, is not used, and is not expired.
    // This prevents TOCTOU race conditions where multiple concurrent requests could both
    // pass the existence check before any are marked as used.
    const consumedChallenge = await this.prisma.walletChallenge.updateMany({
      where: {
        id: input.challengeId,
        walletAddress: input.walletAddress,
        usedAt: null, // Not yet consumed
        expiresAt: {
          gt: new Date(), // Not expired
        },
      },
      data: {
        usedAt: new Date(),
      },
    });

    if (consumedChallenge.count === 0) {
      throw new UnauthorizedException("Challenge is expired or unavailable");
    }

    // Fetch the challenge again to get the message for signature verification.
    // The challenge is now marked as used, so even if verification fails, it cannot be reused.
    const challenge = await this.prisma.walletChallenge.findUnique({
      where: {
        id: input.challengeId,
      },
    });

    if (!challenge) {
      // This should never happen since we just consumed it, but safeguard against deletion.
      throw new UnauthorizedException("Challenge is expired or unavailable");
    }

    const isValid = this.verifySignature(
      input.walletAddress,
      challenge.message,
      input.signature,
    );

    if (!isValid) {
      throw new UnauthorizedException("Invalid wallet signature");
    }

    const walletHash = `sha256:${sha256(input.walletAddress)}`;
    const user = await this.prisma.user.upsert({
      where: {
        walletAddress: input.walletAddress,
      },
      update: {
        walletHash,
        lastLoginAt: new Date(),
      },
      create: {
        walletAddress: input.walletAddress,
        walletHash,
        lastLoginAt: new Date(),
      },
    });

    const token = this.authTokenService.sign({
      id: user.id,
      walletAddress: user.walletAddress,
      walletHash: user.walletHash,
      role: user.role,
    });

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
      },
    };
  }

  async getSession(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
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
