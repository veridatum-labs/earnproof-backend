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
  VerificationOutcome,
} from "@prisma/client";
import { createHmac, randomUUID } from "crypto";
import { VerificationEventService } from "../audit/verification-event.service";
import { AuthenticatedUser } from "../auth/auth.types";
import { sha256 } from "../common/crypto/hash";
import { decryptProtectedAmount } from "../common/crypto/protected-amount";
import { PrismaService } from "../database/prisma.service";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";
import {
  CreateRecurringIncomeProofDto,
  IntervalUnit,
} from "./dto/create-recurring-income-proof.dto";

const SCHEMA_VERSION = "earnproof.minimum-income.v1";
const SCHEMA_VERSION_RECURRING = "earnproof.recurring-income.v1";
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

type RecurringIncomeCredential = {
  id: string;
  type: "EarnProofRecurringIncomeCredential";
  schemaVersion: string;
  issuer: "earnproof-backend";
  subject: {
    walletHash: string;
  };
  claim: {
    /** Cadence descriptor, e.g. "monthly:3" */
    cadence: string;
    intervalUnit: IntervalUnit;
    intervalCount: number;
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
    private readonly verificationEventService: VerificationEventService,
    @Optional()
    private readonly contractAnchoringService?: ContractAnchoringService,
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

    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signCredential(credential),
      anchoring: anchorResult ?? {
        anchored: false,
        reason: "disabled",
      },
    };
  }

  async createRecurringIncomeProof(
    user: AuthenticatedUser,
    input: CreateRecurringIncomeProofDto,
  ) {
    const periodStart = new Date(input.periodStart);
    const periodEnd = new Date(input.periodEnd);

    if (periodStart >= periodEnd) {
      throw new BadRequestException("periodStart must be before periodEnd");
    }

    // Build the interval boundaries up-front so we can validate them before
    // touching the database.
    const intervals = this.buildIntervals(
      periodStart,
      periodEnd,
      input.intervalUnit,
      input.intervalCount,
    );

    const selectedPaymentIds = [...new Set(input.selectedPaymentIds)];
    const payments = await this.prisma.payment.findMany({
      where: {
        id: { in: selectedPaymentIds },
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

    // Evaluate cadence: every required interval must contain at least one
    // qualifying payment. A gap in any interval is an unsatisfied result —
    // we must never issue a credential in that case.
    const unsatisfiedIntervals = intervals.filter(
      ([iStart, iEnd]) =>
        !payments.some(
          (p) => p.occurredAt >= iStart && p.occurredAt <= iEnd,
        ),
    );

    if (unsatisfiedIntervals.length > 0) {
      throw new BadRequestException(
        `Recurring income proof unsatisfied: ${unsatisfiedIntervals.length} of ${intervals.length} interval(s) contain no qualifying payment`,
      );
    }

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() +
        (input.expiresInDays ?? DEFAULT_EXPIRY_DAYS) * 24 * 60 * 60 * 1000,
    );

    const cadence = `${input.intervalUnit}:${input.intervalCount}`;
    const proofId = randomUUID();
    const draftCredential = this.buildRecurringIncomeCredential({
      id: proofId,
      walletHash: user.walletHash,
      cadence,
      intervalUnit: input.intervalUnit,
      intervalCount: input.intervalCount,
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
        proofType: ProofType.RECURRING_INCOME,
        schemaVersion: SCHEMA_VERSION_RECURRING,
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
            operator: "recurring",
            frequency: cadence,
            result: true,
            disclosurePolicy: {
              exactIncomeHidden: true,
              sourceTransactionsHidden: true,
              qualifyingPaymentCount: payments.length,
              intervalUnit: input.intervalUnit,
              intervalCount: input.intervalCount,
            },
          },
        },
      },
      include: { claim: true },
    });

    const credential = this.buildRecurringIncomeCredential({
      id: proof.id,
      walletHash: user.walletHash,
      cadence,
      intervalUnit: input.intervalUnit,
      intervalCount: input.intervalCount,
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
        where: { id: proof.id },
        data: { contractTransactionHash: anchorResult.transactionHash },
      });
    }

    return {
      proofId: proof.id,
      status: proof.status,
      verificationUrl: `/api/v1/proofs/${proof.id}/verify`,
      credential: this.signRecurringIncomeCredential(credential),
      anchoring: anchorResult ?? { anchored: false, reason: "disabled" },
    };
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
      // Fail-open policy: record event asynchronously
      // If event recording fails, the verification response is still returned.
      // This ensures verification availability over audit completeness.
      this.verificationEventService.recordEvent(
        VerificationOutcome.UNKNOWN,
        proofId,
        {
          outcome: "UNKNOWN",
          timestamp: new Date(),
        },
      ).catch(() => {
        // Error already logged by the service
        // Verification continues unblocked
      });

      return {
        result: VerificationResult.UNKNOWN_PROOF,
        status: "unknown",
      };
    }

    const { credential: builtCredential, signedCredential } = this.rebuildAndSign(
      proof as {
        id: string;
        proofType: ProofType;
        assetCode: string;
        assetIssuer: string | null;
        periodStart: Date | null;
        periodEnd: Date | null;
        createdAt: Date;
        expiresAt: Date;
        user: { walletHash: string };
        claim: {
          thresholdEncrypted: string | null;
          frequency: string | null;
          disclosurePolicy: Prisma.JsonValue;
        };
      },
    );
    const expectedHash = `sha256:${sha256(this.canonicalize(builtCredential))}`;

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

    // Convert VerificationResult to VerificationOutcome for event recording
    const outcome = this.mapResultToOutcome(result);

    // Fail-open policy: record verification event asynchronously
    // If event recording fails, the verification response is still returned.
    // This ensures verification availability over audit completeness.
    // Event recording errors are caught and logged by the service.
    this.verificationEventService.recordEvent(outcome, proof.id, {
      outcome: outcome,
      timestamp: new Date(),
    }).catch(() => {
      // Error already logged by the service
      // Verification continues unblocked
    });

    await this.prisma.verificationEvent.create({
      data: {
        proofId: proof.id,
        result,
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

  private buildRecurringIncomeCredential(input: {
    id: string;
    walletHash: string;
    cadence: string;
    intervalUnit: IntervalUnit;
    intervalCount: number;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date;
    periodEnd: Date;
    qualifyingPaymentCount: number;
    issuedAt: Date;
    expiresAt: Date;
  }): RecurringIncomeCredential {
    return {
      id: input.id,
      type: "EarnProofRecurringIncomeCredential",
      schemaVersion: SCHEMA_VERSION_RECURRING,
      issuer: "earnproof-backend",
      subject: { walletHash: input.walletHash },
      claim: {
        cadence: input.cadence,
        intervalUnit: input.intervalUnit,
        intervalCount: input.intervalCount,
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

  private signRecurringIncomeCredential(credential: RecurringIncomeCredential) {
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

  /**
   * Rebuilds the unsigned credential from stored DB values and signs it.
   * Dispatches on proofType so the hash produced here matches the one
   * computed at issuance time.
   */
  private rebuildAndSign(proof: {
    id: string;
    proofType: ProofType;
    assetCode: string;
    assetIssuer: string | null;
    periodStart: Date | null;
    periodEnd: Date | null;
    createdAt: Date;
    expiresAt: Date;
    user: { walletHash: string };
    claim: {
      thresholdEncrypted: string | null;
      frequency: string | null;
      disclosurePolicy: Prisma.JsonValue;
    };
  }) {
    if (proof.proofType === ProofType.RECURRING_INCOME) {
      const { intervalUnit, intervalCount } = this.revealCadence(
        proof.claim.frequency,
      );
      const cadence = proof.claim.frequency ?? `${intervalUnit}:${intervalCount}`;
      const credential = this.buildRecurringIncomeCredential({
        id: proof.id,
        walletHash: proof.user.walletHash,
        cadence,
        intervalUnit,
        intervalCount,
        assetCode: proof.assetCode,
        assetIssuer: proof.assetIssuer,
        periodStart: proof.periodStart ?? proof.createdAt,
        periodEnd: proof.periodEnd ?? proof.createdAt,
        qualifyingPaymentCount: this.qualifyingPaymentCount(proof.claim),
        issuedAt: proof.createdAt,
        expiresAt: proof.expiresAt,
      });
      return {
        credential,
        signedCredential: this.signRecurringIncomeCredential(credential),
      };
    }

    // Default: minimum-income (and any other future type that follows the same shape)
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
    return {
      credential,
      signedCredential: this.signCredential(credential),
    };
  }

  /**
   * Splits [periodStart, periodEnd] into exactly `intervalCount` sub-intervals
   * of the given unit. Each interval is [start, end] inclusive.
   *
   * "month" boundaries are calendar-month-aware: interval i starts at
   * periodStart + i months. "week" is 7 days. "day" is 1 day.
   */
  private buildIntervals(
    periodStart: Date,
    periodEnd: Date,
    unit: IntervalUnit,
    count: number,
  ): [Date, Date][] {
    const intervals: [Date, Date][] = [];

    for (let i = 0; i < count; i++) {
      const iStart = this.addUnit(periodStart, unit, i);
      // The interval ends 1 ms before the next interval starts (exclusive upper)
      // so that a payment exactly on the boundary is in exactly one interval.
      const iEnd =
        i < count - 1
          ? new Date(this.addUnit(periodStart, unit, i + 1).getTime() - 1)
          : periodEnd;

      intervals.push([iStart, iEnd]);
    }

    return intervals;
  }

  private addUnit(base: Date, unit: IntervalUnit, n: number): Date {
    if (n === 0) return new Date(base);

    const d = new Date(base);
    switch (unit) {
      case "day":
        d.setUTCDate(d.getUTCDate() + n);
        break;
      case "week":
        d.setUTCDate(d.getUTCDate() + n * 7);
        break;
      case "month":
        d.setUTCMonth(d.getUTCMonth() + n);
        break;
    }
    return d;
  }

  /**
   * Parses a cadence string stored as "intervalUnit:intervalCount" back into
   * its components. Defaults to "month" + 1 if the stored value is malformed.
   */
  private revealCadence(frequency: string | null): {
    intervalUnit: IntervalUnit;
    intervalCount: number;
  } {
    if (frequency) {
      const parts = frequency.split(":");
      if (parts.length === 2) {
        const unit = parts[0] as IntervalUnit;
        const count = parseInt(parts[1], 10);
        if (["day", "week", "month"].includes(unit) && !isNaN(count)) {
          return { intervalUnit: unit, intervalCount: count };
        }
      }
    }
    return { intervalUnit: "month", intervalCount: 1 };
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

  private mapResultToOutcome(result: VerificationResult): VerificationOutcome {
    switch (result) {
      case VerificationResult.VALID:
        return VerificationOutcome.VALID;
      case VerificationResult.EXPIRED:
        return VerificationOutcome.EXPIRED;
      case VerificationResult.REVOKED:
        return VerificationOutcome.REVOKED;
      case VerificationResult.INVALID_SIGNATURE:
        return VerificationOutcome.INVALID_SIGNATURE;
      case VerificationResult.UNKNOWN_PROOF:
        return VerificationOutcome.UNKNOWN;
      case VerificationResult.UNVERIFIED_ISSUER:
        return VerificationOutcome.ISSUER_WARNING;
      default:
        return VerificationOutcome.UNKNOWN;
    }
  }

  async getVerificationStats(userId: string, proofId: string) {
    // Verify proof ownership: only the owner or admin can view stats
    const proof = await this.prisma.proof.findUnique({
      where: {
        id: proofId,
      },
      select: {
        id: true,
        userId: true,
      },
    });

    if (!proof) {
      throw new NotFoundException("Proof not found");
    }

    if (proof.userId !== userId) {
      throw new ForbiddenException(
        "You do not have permission to view statistics for this proof",
      );
    }

    return this.verificationEventService.getAggregateStats(proofId);
  }
}
