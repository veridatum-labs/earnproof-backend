import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Optional,
  NotFoundException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import {
  PaymentClassification,
  Prisma,
  ProofStatus,
  ProofType,
  VerificationResult,
} from "@prisma/client";
import { createHmac, randomUUID } from "crypto";
import { AuthenticatedUser } from "../auth/auth.types";
import { sha256 } from "../common/crypto/hash";
import { decryptProtectedAmount } from "../common/crypto/protected-amount";
import { PrismaService } from "../database/prisma.service";
import { WebhookDeliveryService } from "../webhooks/webhook-delivery.service";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";

const SCHEMA_VERSION = "earnproof.minimum-income.v1";
const DEFAULT_EXPIRY_DAYS = 30;

type MinimumIncomeCredential = {
  id: string;
  type: "EarnProofMinimumIncomeCredential";
  schemaVersion: string;
  issuer: "earnproof-backend";
  subject: {
    walletHash: string;
  };
  claim: {
    operator: "gte";
    thresholdAmount: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: string;
    periodEnd: string;
    qualifyingPaymentCount: number;
  };
  privacy: {
    exactIncomeHidden: true;
    sourceTransactionsHidden: true;
  };
  issuedAt: string;
  expiresAt: string;
};

@Injectable()
export class ProofsService {
  private readonly signingSecret: string;
  private readonly paymentEncryptionKey: string;
  private readonly stellarNetwork: string;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
    @Optional()
    private readonly contractAnchoringService?: ContractAnchoringService,
    @Optional()
    private readonly webhookDeliveryService?: WebhookDeliveryService,
  ) {
    this.signingSecret = configService.getOrThrow<string>(
      "credentialSigningSecret",
    );
    this.paymentEncryptionKey = configService.getOrThrow<string>(
      "paymentEncryptionKey",
    );
    this.stellarNetwork = configService.getOrThrow<string>("stellar.network");
  }

  async createMinimumIncomeProof(
    user: AuthenticatedUser,
    input: CreateMinimumIncomeProofDto,
  ) {
    const periodStart = new Date(input.periodStart);
    const periodEnd = new Date(input.periodEnd);

    if (periodStart > periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    const selectedPaymentIds = [...new Set(input.selectedPaymentIds)];
    const payments = await this.prisma.payment.findMany({
      where: {
        id: {
          in: selectedPaymentIds,
        },
        userId: user.id,
      },
      select: {
        id: true,
        assetCode: true,
        assetIssuer: true,
        amountEncrypted: true,
        classification: true,
        isEligible: true,
        occurredAt: true,
      },
    });

    if (payments.length !== selectedPaymentIds.length) {
      throw new BadRequestException("One or more selected payments are invalid");
    }

    for (const payment of payments) {
      if (
        payment.classification !== PaymentClassification.INCOME ||
        !payment.isEligible
      ) {
        throw new BadRequestException(
          "Selected payments must be eligible income payments",
        );
      }

      if (
        payment.assetCode !== input.assetCode ||
        (payment.assetIssuer ?? null) !== (input.assetIssuer ?? null)
      ) {
        throw new BadRequestException(
          "Selected payments must use the requested asset",
        );
      }

      if (payment.occurredAt < periodStart || payment.occurredAt > periodEnd) {
        throw new BadRequestException(
          "Selected payments must fall inside the requested period",
        );
      }
    }

    const total = payments.reduce(
      (sum, payment) => sum + this.revealProtectedAmount(payment.amountEncrypted),
      0n,
    );
    const threshold = this.parseAmount(input.thresholdAmount);

    if (total < threshold) {
      throw new BadRequestException(
        "Selected payments do not satisfy the minimum income threshold",
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );

    const proofId = randomUUID();
    const draftCredential = this.buildCredential({
      id: proofId,
      walletHash: user.walletHash,
      thresholdAmount: input.thresholdAmount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: now,
      expiresAt,
    });
    const credentialHash = `sha256:${sha256(this.canonicalize(draftCredential))}`;

    const proof = await this.prisma.proof.create({
      data: {
        id: proofId,
        userId: user.id,
        proofType: ProofType.MINIMUM_INCOME,
        schemaVersion: SCHEMA_VERSION,
        status: ProofStatus.ACTIVE,
        network: this.stellarNetwork,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer ?? null,
        periodStart,
        periodEnd,
        expiresAt,
        createdAt: now,
        credentialHash,
        commitment: `sha256:${sha256(credentialHash)}`,
        claim: {
          create: {
            operator: "gte",
            thresholdEncrypted: this.protectAmount(input.thresholdAmount),
            result: true,
            disclosurePolicy: {
              exactIncomeHidden: true,
              sourceTransactionsHidden: true,
              qualifyingPaymentCount: payments.length,
            },
          },
        },
      },
      include: {
        claim: true,
      },
    });

    const credential = this.buildCredential({
      id: proof.id,
      walletHash: user.walletHash,
      thresholdAmount: input.thresholdAmount,
      assetCode: input.assetCode,
      assetIssuer: input.assetIssuer ?? null,
      periodStart,
      periodEnd,
      qualifyingPaymentCount: payments.length,
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });
    const anchorResult = await this.contractAnchoringService?.anchorProof({
      proofId: proof.id,
      commitment: proof.commitment ?? credentialHash,
      expiresAt: proof.expiresAt,
    });

    if (anchorResult?.anchored) {
      await this.prisma.proof.update({
        where: {
          id: proof.id,
        },
        data: {
          contractTransactionHash: anchorResult.transactionHash,
        },
      });
    }

    const result = {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchorResult ?? {
        anchored: false,
        reason: "disabled",
      },
    };

    // Emit proof.created webhook — fire-and-forget, must not throw.
    void this.webhookDeliveryService?.enqueueForUser(user.id, "proof.created", {
      event: "proof.created",
      data: {
        proofId: proof.id,
        proofType: proof.proofType,
        schemaVersion: proof.schemaVersion,
        status: proof.status,
        network: proof.network,
        assetCode: proof.assetCode,
        assetIssuer: proof.assetIssuer,
        periodStart: proof.periodStart?.toISOString() ?? null,
        periodEnd: proof.periodEnd?.toISOString() ?? null,
        expiresAt: proof.expiresAt.toISOString(),
        credentialHash: proof.credentialHash,
        contractTransactionHash: anchorResult?.anchored
          ? (anchorResult.transactionHash ?? null)
          : null,
        issuedAt: proof.createdAt.toISOString(),
      },
    });

    return result;
  }

  async revokeProof(userId: string, proofId: string) {
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      select: {
        id: true,
        userId: true,
        status: true,
        contractTransactionHash: true,
      },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    if (proof.userId !== userId) {
      throw new ForbiddenException("Proof does not belong to this user");
    }

    const contractRevocation = proof.contractTransactionHash
      ? await this.contractAnchoringService?.revokeProof(proof.id)
      : undefined;

    const updated = await this.prisma.proof.update({
      where: {
        id: proof.id,
      },
      data: {
        status: ProofStatus.REVOKED,
        revokedAt: new Date(),
      },
      select: {
        id: true,
        status: true,
        revokedAt: true,
      },
    });

    // Emit proof.revoked webhook — fire-and-forget, must not throw.
    void this.webhookDeliveryService?.enqueueForUser(userId, "proof.revoked", {
      event: "proof.revoked",
      data: {
        proofId: updated.id,
        status: updated.status,
        revokedAt: updated.revokedAt!.toISOString(),
      },
    });

    return {
      ...updated,
      anchoring: contractRevocation ?? {
        anchored: false,
        reason: "disabled",
      },
    };
  }

  async verifyProof(proofId: string) {
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      include: {
        user: {
          select: {
            walletHash: true,
          },
        },
        claim: true,
      },
    });

    if (!proof || !proof.claim) {
      return {
        result: VerificationResult.UNKNOWN_PROOF,
        status: "unknown",
      };
    }

    const credential = this.buildCredential({
      id: proof.id,
      walletHash: proof.user.walletHash,
      thresholdAmount: this.revealThreshold(proof.claim.thresholdEncrypted),
      assetCode: proof.assetCode,
      assetIssuer: proof.assetIssuer,
      periodStart: proof.periodStart ?? proof.createdAt,
      periodEnd: proof.periodEnd ?? proof.createdAt,
      qualifyingPaymentCount: this.qualifyingPaymentCount(proof.claim),
      issuedAt: proof.createdAt,
      expiresAt: proof.expiresAt,
    });
    const signedCredential = this.signCredential(credential);
    const expectedHash = `sha256:${sha256(this.canonicalize(credential))}`;

    let result: VerificationResult = VerificationResult.VALID;
    if (proof.credentialHash !== expectedHash) {
      result = VerificationResult.INVALID_SIGNATURE;
    } else if (proof.status === ProofStatus.REVOKED) {
      result = VerificationResult.REVOKED;
    } else if (proof.expiresAt <= new Date()) {
      result = VerificationResult.EXPIRED;
    } else if (proof.status !== ProofStatus.ACTIVE) {
      result = VerificationResult.INVALID_SIGNATURE;
    }

    const contractStatus = proof.contractTransactionHash
      ? await this.contractAnchoringService?.getProofStatus(proof.id)
      : undefined;

    if (contractStatus?.checked) {
      if (contractStatus.revoked) {
        result = VerificationResult.REVOKED;
      } else if (result === VerificationResult.VALID && !contractStatus.valid) {
        result = VerificationResult.INVALID_SIGNATURE;
      }
    }

    await this.prisma.verificationEvent.create({
      data: {
        proofId: proof.id,
        result,
      },
    });

    // Emit proof.verified webhook — fire-and-forget, must not throw.
    void this.webhookDeliveryService?.enqueueForUser(proof.userId, "proof.verified", {
      event: "proof.verified",
      data: {
        proofId: proof.id,
        result,
        verifiedAt: new Date().toISOString(),
      },
    });

    return {
      result,
      status: this.publicStatus(result),
      credential: signedCredential,
      proof: {
        id: proof.id,
        type: proof.proofType,
        schemaVersion: proof.schemaVersion,
        network: proof.network,
        issuedAt: proof.createdAt.toISOString(),
        expiresAt: proof.expiresAt.toISOString(),
        revokedAt: proof.revokedAt?.toISOString() ?? null,
        contractStatus: contractStatus ?? {
          checked: false,
          reason: "disabled",
        },
      },
    };
  }

  private buildCredential(input: {
    id: string;
    walletHash: string;
    thresholdAmount: string;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    qualifyingPaymentCount: number;
    issuedAt: Date;
    expiresAt: Date;
  }): MinimumIncomeCredential {
    return {
      id: input.id,
      type: "EarnProofMinimumIncomeCredential",
      schemaVersion: SCHEMA_VERSION,
      issuer: "earnproof-backend",
      subject: {
        walletHash: input.walletHash,
      },
      claim: {
        operator: "gte",
        thresholdAmount: input.thresholdAmount,
        assetCode: input.assetCode,
        assetIssuer: input.assetIssuer,
        periodStart: input.periodStart.toISOString(),
        periodEnd: input.periodEnd.toISOString(),
        qualifyingPaymentCount: input.qualifyingPaymentCount,
      },
      privacy: {
        exactIncomeHidden: true,
        sourceTransactionsHidden: true,
      },
      issuedAt: input.issuedAt.toISOString(),
      expiresAt: input.expiresAt.toISOString(),
    };
  }

  private signCredential(credential: MinimumIncomeCredential) {
    const canonicalPayload = this.canonicalize(credential);
    return {
      ...credential,
      proof: {
        type: "HMAC-SHA256",
        credentialHash: `sha256:${sha256(canonicalPayload)}`,
        signature: `hmac-sha256:${createHmac("sha256", this.signingSecret)
          .update(canonicalPayload)
          .digest("base64url")}`,
      },
    };
  }

  private canonicalize(value: unknown): string {
    return JSON.stringify(this.sortObject(value));
  }

  private sortObject(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((item) => this.sortObject(item));
    }

    if (value && typeof value === "object") {
      const record = value as Record<string, unknown>;
      return Object.keys(record)
        .sort()
        .reduce<Record<string, unknown>>((sorted, key) => {
          sorted[key] = this.sortObject(record[key]);
          return sorted;
        }, {});
    }

    return value;
  }

  private revealProtectedAmount(amountEncrypted: string | null) {
    if (!amountEncrypted) {
      throw new BadRequestException("Selected payment amount is unavailable");
    }

    try {
      return this.parseAmount(
        decryptProtectedAmount(amountEncrypted, this.paymentEncryptionKey),
      );
    } catch {
      throw new BadRequestException("Selected payment amount is unavailable");
    }
  }

  private revealThreshold(thresholdEncrypted: string | null) {
    if (!thresholdEncrypted?.startsWith("redacted:")) {
      return "0";
    }

    return Buffer.from(
      thresholdEncrypted.slice("redacted:".length),
      "base64url",
    ).toString("utf8");
  }

  private protectAmount(amount: string) {
    return `redacted:${Buffer.from(amount).toString("base64url")}`;
  }

  private parseAmount(amount: string) {
    const [whole, decimal = ""] = amount.split(".");
    const paddedDecimal = decimal.padEnd(7, "0");
    return BigInt(whole) * 10_000_000n + BigInt(paddedDecimal);
  }

  private qualifyingPaymentCount(claim: { disclosurePolicy: Prisma.JsonValue }) {
    const policy = claim.disclosurePolicy;
    if (
      policy &&
      typeof policy === "object" &&
      !Array.isArray(policy) &&
      "qualifyingPaymentCount" in policy
    ) {
      const count = policy.qualifyingPaymentCount;
      return typeof count === "number" ? count : 1;
    }

    return 1;
  }

  private publicStatus(result: VerificationResult) {
    switch (result) {
      case VerificationResult.VALID:
        return "valid";
      case VerificationResult.EXPIRED:
        return "expired";
      case VerificationResult.REVOKED:
        return "revoked";
      case VerificationResult.UNKNOWN_PROOF:
        return "unknown";
      default:
        return "invalid";
    }
  }
}
