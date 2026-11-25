import { Injectable } from "@nestjs/common";
import { PrismaService } from "../database/prisma.service";
import { createHmac } from "crypto";

/**
 * Minimal, privacy-safe deletion tombstone for a payment.
 *
 * When a payment is removed by retention or a privacy request, a tombstone is
 * persisted so that a later Horizon sync cannot silently reingest the same
 * payment. Only a keyed cryptographic commitment is stored — never the raw
 * memo, wallet address, signature, amount, or any other deleted payment
 * payload.
 */

export interface TombstoneRecord {
  ownerId: string;
  sourceIdentityCommitment: string;
  expiresAt: Date;
}

export interface TombstoneStore {
  upsert(record: TombstoneRecord): Promise<void>;
  findActive(
    ownerId: string,
    sourceIdentityCommitment: string,
    now: Date,
  ): Promise<TombstoneRecord | null>;
}

/**
 * Computes the owner-scoped, collision-resistant commitment stored in a
 * tombstone. Keyed with a server-side pepper so the commitment cannot be
 * reversed or precomputed by an attacker who knows the owner, account, and
 * payment identifiers.
 *
 * Inputs are identifiers only: ownerId, accountId (the monitored account /
 * wallet the payment landed on), and paymentId (the Horizon operation id).
 * No payment payload is ever part of the commitment.
 */
export function computeSourceIdentityCommitment(params: {
  pepper: string;
  ownerId: string;
  accountId: string;
  paymentId: string;
}): string {
  return createHmac("sha256", params.pepper)
    .update(
      `${params.ownerId}|${params.accountId}|${params.paymentId}`,
      "utf8",
    )
    .digest("hex");
}

/**
 * Prisma-backed implementation of {@link TombstoneStore}.
 *
 * A tombstone is active while `expiresAt` is in the future. The unique index
 * on (ownerId, sourceIdentityCommitment) makes the commitment collision
 * resistant: re-recording a deletion for the same payment renews the expiry
 * rather than duplicating the row.
 */
@Injectable()
export class PrismaTombstoneStore implements TombstoneStore {
  constructor(private readonly prisma: PrismaService) {}

  async upsert(record: TombstoneRecord): Promise<void> {
    await this.prisma.paymentDeletionTombstone.upsert({
      where: {
        ownerId_sourceIdentityCommitment: {
          ownerId: record.ownerId,
          sourceIdentityCommitment: record.sourceIdentityCommitment,
        },
      },
      update: {
        expiresAt: record.expiresAt,
      },
      create: {
        ownerId: record.ownerId,
        sourceIdentityCommitment: record.sourceIdentityCommitment,
        expiresAt: record.expiresAt,
      },
    });
  }

  async findActive(
    ownerId: string,
    sourceIdentityCommitment: string,
    now: Date,
  ): Promise<TombstoneRecord | null> {
    const row = await this.prisma.paymentDeletionTombstone.findFirst({
      where: {
        ownerId,
        sourceIdentityCommitment,
        expiresAt: { gt: now },
      },
      select: {
        ownerId: true,
        sourceIdentityCommitment: true,
        expiresAt: true,
      },
    });
    if (!row) return null;
    return {
      ownerId: row.ownerId,
      sourceIdentityCommitment: row.sourceIdentityCommitment,
      expiresAt: row.expiresAt,
    };
  }
}

/**
 * Service layer for deletion tombstones.
 *
 * The pepper is drawn from `PAYMENT_TOMBSTONE_PEPPER` (or falls back to the
 * payment encryption key material so a deployment always has a server secret
 * available without a new environment variable).
 */
@Injectable()
export class PaymentTombstoneService {
  constructor(
    private readonly store: TombstoneStore,
    private readonly pepper: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** Records a deletion tombstone for a payment removed by retention or privacy. */
  async recordDeletionTombstone(params: {
    ownerId: string;
    accountId: string;
    paymentId: string;
    retentionDays: number;
    reason?: string;
  }): Promise<TombstoneRecord> {
    const current = this.now();
    const commitment = computeSourceIdentityCommitment({
      pepper: this.pepper,
      ownerId: params.ownerId,
      accountId: params.accountId,
      paymentId: params.paymentId,
    });
    const expiresAt = new Date(
      current.getTime() + Math.max(1, params.retentionDays) * 86_400_000,
    );

    const record: TombstoneRecord = {
      ownerId: params.ownerId,
      sourceIdentityCommitment: commitment,
      expiresAt,
    };
    await this.store.upsert(record);
    return record;
  }

  /** True while an active (unexpired) tombstone blocks reingestion of this payment. */
  async shouldBlockReingestion(params: {
    ownerId: string;
    accountId: string;
    paymentId: string;
  }): Promise<boolean> {
    const commitment = computeSourceIdentityCommitment({
      pepper: this.pepper,
      ownerId: params.ownerId,
      accountId: params.accountId,
      paymentId: params.paymentId,
    });
    const active = await this.store.findActive(
      params.ownerId,
      commitment,
      this.now(),
    );
    return active !== null;
  }
}
