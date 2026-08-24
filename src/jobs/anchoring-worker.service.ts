import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Interval } from "@nestjs/schedule";
import { AnchoringOperation, AnchoringStatus } from "@prisma/client";
import { PrismaService } from "../database/prisma.service";
import {
  AnchorProofInput,
  ContractAnchoringService,
} from "../proofs/contract-anchoring.service";

/**
 * Maximum number of delivery attempts before an intent is permanently failed.
 * Intentionally capped so that unrecoverable errors (e.g., contract already
 * registered) do not retry indefinitely.
 */
const MAX_ATTEMPTS = 10;

/**
 * Base backoff delay in milliseconds (30 s).
 * Each retry doubles the delay up to BACKOFF_CAP_MS.
 */
const BACKOFF_BASE_MS = 30_000;

/** Maximum backoff ceiling (1 hour). */
const BACKOFF_CAP_MS = 60 * 60_000;

/**
 * Number of intents to claim per poll cycle.
 * Keeps a single worker instance from monopolising all pending work on startup.
 */
const BATCH_SIZE = 5;

/**
 * Intents that have been in PROCESSING for longer than this duration are
 * presumed to belong to a crashed worker and are reset to PENDING.
 */
const STALE_PROCESSING_THRESHOLD_MS = 5 * 60_000;

/**
 * Error message substrings that indicate a permanent failure.
 * These are matched case-insensitively against the sanitised error text.
 */
const PERMANENT_ERROR_PATTERNS: RegExp[] = [
  /already registered/i,
  /already exists/i,
  /proof not found/i,
  /invalid contract id/i,
  /contract not found/i,
  /unauthorized/i,
  /access denied/i,
];

/**
 * Strip potential secrets from an error message before storing.
 * Removes Stellar secret-key-like tokens (S…56 chars) and KEY=VALUE pairs.
 */
function sanitiseError(message: string): string {
  return message
    .replace(/S[A-Z2-7]{55}/g, "[REDACTED_SECRET]")
    .replace(/\b[A-Z_]{3,}=[^\s]+/g, "[REDACTED_ENV]")
    .slice(0, 500); // cap length to avoid unbounded storage
}

function isPermanentError(message: string): boolean {
  return PERMANENT_ERROR_PATTERNS.some((pattern) => pattern.test(message));
}

function computeNextRetryAt(attemptCount: number): Date {
  const delayMs = Math.min(
    BACKOFF_BASE_MS * Math.pow(2, attemptCount - 1),
    BACKOFF_CAP_MS,
  );
  return new Date(Date.now() + delayMs);
}

@Injectable()
export class AnchoringWorkerService {
  private readonly logger = new Logger(AnchoringWorkerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly anchoring: ContractAnchoringService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Main poll loop — runs every 10 seconds.
   *
   * Two phases per tick:
   * 1. Reset stale PROCESSING intents (crash recovery).
   * 2. Claim and process a batch of PENDING intents.
   */
  @Interval(10_000)
  async poll(): Promise<void> {
    if (!this.config.get<boolean>("contractAnchoring.enabled")) {
      return;
    }

    await this.resetStaleProcessing();
    await this.processBatch();
  }

  /**
   * Exposed for testing — processes a single intent by ID without going through
   * the poll/claim cycle.
   */
  async processIntent(intentId: string): Promise<void> {
    const intent = await this.prisma.anchoringIntent.findUnique({
      where: { id: intentId },
      include: { proof: { select: { commitment: true, expiresAt: true } } },
    });

    if (!intent) {
      this.logger.warn(`AnchoringIntent ${intentId} not found`);
      return;
    }

    if (
      intent.status === AnchoringStatus.CONFIRMED ||
      intent.status === AnchoringStatus.FAILED
    ) {
      // Already terminal — nothing to do. Handles duplicate delivery.
      return;
    }

    await this.executeIntent(intent);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async resetStaleProcessing(): Promise<void> {
    const staleThreshold = new Date(Date.now() - STALE_PROCESSING_THRESHOLD_MS);

    const reset = await this.prisma.anchoringIntent.updateMany({
      where: {
        status: AnchoringStatus.PROCESSING,
        lastAttemptAt: { lt: staleThreshold },
      },
      data: {
        status: AnchoringStatus.PENDING,
        nextRetryAt: new Date(), // eligible immediately
      },
    });

    if (reset.count > 0) {
      this.logger.warn(
        `Reset ${reset.count} stale PROCESSING intent(s) to PENDING`,
      );
    }
  }

  private async processBatch(): Promise<void> {
    const now = new Date();

    // Claim a batch atomically: move PENDING → PROCESSING in one update so
    // concurrent workers on multi-replica deployments do not double-process.
    // We first SELECT the IDs, then UPDATE to PROCESSING in a transaction.
    const claimed = await this.prisma.$transaction(async (tx) => {
      const candidates = await tx.anchoringIntent.findMany({
        where: {
          status: AnchoringStatus.PENDING,
          OR: [{ nextRetryAt: null }, { nextRetryAt: { lte: now } }],
        },
        orderBy: { createdAt: "asc" },
        take: BATCH_SIZE,
        select: { id: true },
      });

      if (candidates.length === 0) return [];

      const ids = candidates.map((c) => c.id);

      await tx.anchoringIntent.updateMany({
        where: { id: { in: ids }, status: AnchoringStatus.PENDING },
        data: { status: AnchoringStatus.PROCESSING, lastAttemptAt: now },
      });

      return tx.anchoringIntent.findMany({
        where: { id: { in: ids } },
        include: { proof: { select: { commitment: true, expiresAt: true } } },
      });
    });

    for (const intent of claimed) {
      await this.executeIntent(intent);
    }
  }

  private async executeIntent(
    intent: Awaited<ReturnType<typeof this.prisma.anchoringIntent.findUnique>> & {
      proof: { commitment: string | null; expiresAt: Date };
    },
  ): Promise<void> {
    if (!intent) return;

    const { id, proofId, operation, attemptCount, proof } = intent;

    // Idempotency guard: if a CONFIRMED record already exists for this
    // (proofId, operation) pair, mark this intent confirmed and skip the CLI.
    const existing = await this.prisma.anchoringIntent.findFirst({
      where: {
        proofId,
        operation,
        status: AnchoringStatus.CONFIRMED,
        id: { not: id },
      },
      select: { transactionHash: true, ledger: true },
    });

    if (existing) {
      await this.prisma.anchoringIntent.update({
        where: { id },
        data: {
          status: AnchoringStatus.CONFIRMED,
          transactionHash: existing.transactionHash,
          ledger: existing.ledger,
          lastErrorSafe: null,
        },
      });
      this.logger.log(
        `Intent ${id} confirmed via idempotency check (already confirmed: ${operation} for proof ${proofId})`,
      );
      return;
    }

    const newAttemptCount = attemptCount + 1;

    try {
      let transactionHash: string;

      if (operation === AnchoringOperation.REGISTER) {
        const anchorInput: AnchorProofInput = {
          proofId,
          commitment: proof.commitment ?? proofId,
          expiresAt: proof.expiresAt,
        };
        const result = await this.anchoring.anchorProof(anchorInput);

        if (!result.anchored) {
          // anchorProof returned anchored:false without throwing — treat as
          // transient unless the reason is "disabled" (config issue, permanent).
          const isFatal = result.reason === "disabled";
          throw Object.assign(
            new Error(result.error ?? `Anchoring ${result.reason}`),
            { permanent: isFatal },
          );
        }
        transactionHash = result.transactionHash;
      } else {
        // REVOKE
        const result = await this.anchoring.revokeProof(proofId);

        if (!result.anchored) {
          const isFatal = result.reason === "disabled";
          throw Object.assign(
            new Error(result.error ?? `Revocation ${result.reason}`),
            { permanent: isFatal },
          );
        }
        transactionHash = result.transactionHash;
      }

      // Parse ledger from transaction hash — the CLI may return
      // "<txhash>:<ledger>" or just "<txhash>". Store what we get.
      const [txHash, ledger] = transactionHash.includes(":")
        ? transactionHash.split(":", 2)
        : [transactionHash, undefined];

      // Write CONFIRMED + update Proof.contractTransactionHash in one
      // transaction so a crash between the two writes cannot leave them
      // inconsistent.
      await this.prisma.$transaction([
        this.prisma.anchoringIntent.update({
          where: { id },
          data: {
            status: AnchoringStatus.CONFIRMED,
            attemptCount: newAttemptCount,
            lastAttemptAt: new Date(),
            transactionHash: txHash,
            ledger: ledger ?? null,
            lastErrorSafe: null,
            permanentError: false,
          },
        }),
        this.prisma.proof.update({
          where: { id: proofId },
          data: { contractTransactionHash: txHash },
        }),
      ]);

      this.logger.log(
        `Intent ${id} CONFIRMED: ${operation} for proof ${proofId} tx=${txHash}`,
      );
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Unknown error";
      const permanent =
        (err instanceof Error && (err as Error & { permanent?: boolean }).permanent) ||
        isPermanentError(message) ||
        newAttemptCount >= MAX_ATTEMPTS;

      const safeError = sanitiseError(message);

      if (permanent) {
        await this.prisma.anchoringIntent.update({
          where: { id },
          data: {
            status: AnchoringStatus.FAILED,
            attemptCount: newAttemptCount,
            lastAttemptAt: new Date(),
            nextRetryAt: null,
            lastErrorSafe: safeError,
            permanentError: true,
          },
        });
        this.logger.error(
          `Intent ${id} FAILED permanently: ${operation} for proof ${proofId} — ${safeError}`,
        );
      } else {
        const nextRetryAt = computeNextRetryAt(newAttemptCount);
        await this.prisma.anchoringIntent.update({
          where: { id },
          data: {
            status: AnchoringStatus.PENDING,
            attemptCount: newAttemptCount,
            lastAttemptAt: new Date(),
            nextRetryAt,
            lastErrorSafe: safeError,
            permanentError: false,
          },
        });
        this.logger.warn(
          `Intent ${id} transient failure (attempt ${newAttemptCount}/${MAX_ATTEMPTS}), ` +
            `retry at ${nextRetryAt.toISOString()} — ${safeError}`,
        );
      }
    }
  }
}
