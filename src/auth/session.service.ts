import { Injectable, UnauthorizedException } from "@nestjs/common";
import type { Prisma } from "@prisma/client";
import { ConfigService } from "@nestjs/config";
import { randomBytes } from "crypto";
import { PrismaService } from "../database/prisma.service";
import { sha256 } from "../common/crypto/hash";
import { AuthenticatedUser } from "./auth.types";
import { Clock, SystemClock } from "../common/time/clock";

/** Default session TTL: 12 hours in seconds. */
const DEFAULT_TTL_SECONDS = 60 * 60 * 12;

type SessionLookup = {
  id: string;
  userId: string;
  expiresAt: Date;
  revokedAt: Date | null;
};

export type SessionIdentity = {
  sessionId: string;
  userId: string;
};

/**
 * How the opaque token is structured (internal only).
 *
 * Format: `<sessionId>.<32-byte-random-hex>`
 *
 * The full string is what we hand to the client as a Bearer token.
 * We store only `sha256(<fullToken>)` in the database — the raw token
 * is never persisted or logged.
 */

@Injectable()
export class SessionService {
  private readonly sessionTtlSeconds: number;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
    // Defaults to the real system clock so every existing call site (Nest's
    // DI container, and every test that constructs SessionService directly)
    // keeps working unchanged; pass a FixedClock (test/time/fixed-clock.ts)
    // to control "now" deterministically in boundary tests.
    private readonly clock: Clock = new SystemClock(),
  ) {
    // Re-use the existing SESSION_SECRET env var to confirm the config is
    // present; actual token confidentiality comes from the random bytes,
    // not from HMAC signing.
    configService.getOrThrow<string>("sessionSecret");
    this.sessionTtlSeconds = DEFAULT_TTL_SECONDS;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Create a new persisted session for `user` and return the opaque token.
   * The token is never stored — only its SHA-256 hash is persisted.
   */
  async create(
    user: AuthenticatedUser,
    ttlSeconds = this.sessionTtlSeconds,
  ): Promise<{ token: string; sessionId: string; expiresAt: Date }> {
    const { token, tokenHash, sessionId } = this.generateToken();
    const expiresAt = new Date(this.clock.nowMs() + ttlSeconds * 1000);

    await this.prisma.authSession.create({
      data: {
        id: sessionId,
        tokenHash,
        userId: user.id,
        expiresAt,
      },
    });

    return { token, sessionId, expiresAt };
  }

  /**
   * Validate a Bearer token string.
   *
   * Rejects:
   *  - malformed tokens (wrong format)
   *  - tokens whose session row is missing
   *  - expired sessions (`expiresAt` in the past)
   *  - revoked sessions (`revokedAt` is set)
   *
   * On success updates `lastUsedAt` and returns the session id + userId.
   */
  async validate(
    token: string,
  ): Promise<{ sessionId: string; userId: string }> {
    const tokenHash = this.hashToken(token);
    if (!tokenHash) {
      throw new UnauthorizedException("Malformed session token");
    }

    const session = await this.findSessionByHash(tokenHash);

    if (!session) {
      throw new UnauthorizedException("Session not found");
    }

    if (session.revokedAt !== null) {
      throw new UnauthorizedException("Session has been revoked");
    }

    if (session.expiresAt <= this.clock.now()) {
      throw new UnauthorizedException("Session has expired");
    }

    // Fire-and-forget lastUsedAt update — failure is non-fatal.
    this.prisma.authSession
      .update({
        where: { id: session.id },
        data: { lastUsedAt: this.clock.now() },
      })
      .catch(() => {
        // Deliberately swallowed: a failed timestamp update must not break
        // in-flight requests.
      });

    return { sessionId: session.id, userId: session.userId };
  }

  /**
   * Resolve a live persisted session without mutating `lastUsedAt` or throwing.
   * This is for soft-auth consumers such as global rate limiting; route guards
   * still own authentication enforcement.
   */
  async tryIdentify(token: string): Promise<SessionIdentity | null> {
    const tokenHash = this.hashToken(token);
    if (!tokenHash) return null;

    try {
      const session = await this.findSessionByHash(tokenHash);
      if (!session) return null;
      if (session.revokedAt !== null) return null;
      if (session.expiresAt <= this.clock.now()) return null;
      return { sessionId: session.id, userId: session.userId };
    } catch {
      return null;
    }
  }

  /**
   * Revoke a single session by its database id.
   * Idempotent — revoking an already-revoked session is a no-op.
   *
   * @param sessionId  The AuthSession.id (NOT the raw token).
   */
  async revoke(sessionId: string): Promise<void> {
    await this.prisma.authSession.updateMany({
      where: {
        id: sessionId,
        revokedAt: null, // idempotent guard
      },
      data: { revokedAt: this.clock.now() },
    });
  }

  /**
   * Rotate a session: atomically revoke the current session and issue a fresh
   * one with a new token.  The old session's `rotatedToId` is set to the new
   * session id, making the rotation chain queryable.
   *
   * If `sessionId` is already revoked, throws `UnauthorizedException` to
   * prevent reuse of rotated credentials.
   *
   * @returns  The new opaque token and its metadata.
   */
  async rotate(
    sessionId: string,
    user: AuthenticatedUser,
    ttlSeconds = this.sessionTtlSeconds,
  ): Promise<{ token: string; sessionId: string; expiresAt: Date }> {
    const { token, tokenHash, sessionId: newSessionId } = this.generateToken();
    const expiresAt = new Date(this.clock.nowMs() + ttlSeconds * 1000);

    await this.prisma.$transaction(async (transaction: Prisma.TransactionClient) => {
      const existing = await transaction.authSession.findUnique({
        where: { id: sessionId },
        select: { userId: true, revokedAt: true, expiresAt: true },
      });

      if (!existing || existing.userId !== user.id) {
        throw new UnauthorizedException("Session not found");
      }

      if (existing.revokedAt !== null) {
        throw new UnauthorizedException(
          "Cannot rotate an already-revoked session",
        );
      }

      if (existing.expiresAt <= this.clock.now()) {
        throw new UnauthorizedException("Session has expired");
      }

      await transaction.authSession.create({
        data: {
          id: newSessionId,
          tokenHash,
          userId: user.id,
          expiresAt,
        },
      });

      const revoked = await transaction.authSession.updateMany({
        where: { id: sessionId, userId: user.id, revokedAt: null },
        data: {
          revokedAt: this.clock.now(),
          rotatedToId: newSessionId,
        },
      });

      if (revoked.count !== 1) {
        throw new UnauthorizedException(
          "Cannot rotate an already-revoked session",
        );
      }
    });

    return { token, sessionId: newSessionId, expiresAt };
  }

  /**
   * Revoke all active sessions for a user (e.g. "logout everywhere").
   */
  async revokeAll(userId: string): Promise<void> {
    await this.prisma.authSession.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: { revokedAt: this.clock.now() },
    });
  }

  /**
   * List all sessions for a user, including active, revoked, and expired sessions.
   * Returns only safe, non-sensitive metadata (timestamps, activity flags).
   *
   * @param userId          The user ID to list sessions for.
   * @param currentSessionId The session ID of the requesting session (for marking as current).
   * @returns               Array of session summaries ordered by createdAt descending.
   */
  async listSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<Array<{
    sessionId: string;
    createdAt: Date;
    expiresAt: Date;
    lastUsedAt: Date | null;
    revokedAt: Date | null;
    isActive: boolean;
    isCurrent: boolean;
  }>> {
    const now = this.clock.now();
    const sessions = await this.prisma.authSession.findMany({
      where: { userId },
      select: {
        id: true,
        createdAt: true,
        expiresAt: true,
        lastUsedAt: true,
        revokedAt: true,
      },
      orderBy: { createdAt: "desc" },
    });

    return sessions.map((session) => {
      // A session is active if it's not revoked and hasn't expired yet.
      const isActive = session.revokedAt === null && session.expiresAt > now;

      return {
        sessionId: session.id,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        lastUsedAt: session.lastUsedAt,
        revokedAt: session.revokedAt,
        isActive,
        isCurrent: session.id === currentSessionId,
      };
    });
  }

  /**
   * Revoke a specific session by its database id, scoped to a user.
   * Idempotent — revoking an already-revoked session is a no-op.
   * Fails if the session does not belong to the specified user.
   *
   * @param sessionId  The AuthSession.id (NOT the raw token).
   * @param userId     The user ID that must own this session.
   * @returns          true if the session was revoked, false if it didn't exist or wasn't owned by the user.
   */
  async revokeSpecificSession(
    sessionId: string,
    userId: string,
  ): Promise<boolean> {
    const result = await this.prisma.authSession.updateMany({
      where: {
        id: sessionId,
        userId, // Ensure ownership — never allow cross-user revocation
        revokedAt: null, // idempotent guard: only update if not already revoked
      },
      data: { revokedAt: this.clock.now() },
    });

    return result.count > 0;
  }

  /**
   * Revoke all sessions for a user except one specified session (the current session).
   * This prevents accidental lockout during a bulk "revoke all others" operation.
   *
   * @param userId             The user ID.
   * @param currentSessionId    The session ID to exclude from revocation (typically the current session).
   * @returns                  Number of sessions revoked (not including the current session).
   */
  async revokeAllOtherSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<number> {
    const result = await this.prisma.authSession.updateMany({
      where: {
        userId,
        id: { not: currentSessionId }, // Exclude the current session
        revokedAt: null, // Only revoke active sessions
      },
      data: { revokedAt: this.clock.now() },
    });

    return result.count;
  }

  /**
   * Delete session rows that expired before `olderThan` (defaults to now).
   * Intended to be called by a scheduled cleanup job.
   *
   * @returns  Number of rows deleted.
   */
  async deleteExpired(olderThan: Date = this.clock.now()): Promise<number> {
    const result = await this.prisma.authSession.deleteMany({
      where: { expiresAt: { lt: olderThan } },
    });
    return result.count;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Generate a cryptographically random opaque token and its SHA-256 hash.
   *
   * Token format: `<cuid-style-id>.<32-random-bytes-hex>`
   * The id segment is also used as the database primary key so we avoid a
   * round-trip SELECT after INSERT.
   */
  private generateToken(): {
    token: string;
    tokenHash: string;
    sessionId: string;
  } {
    // 32 random bytes → 64-char hex string (256 bits of entropy)
    const secret = randomBytes(32).toString("hex");
    // Use a separate random id segment so the session id alone does not allow
    // constructing a valid token (the secret part is still required).
    const sessionId = randomBytes(12).toString("base64url");
    const token = `${sessionId}.${secret}`;
    const tokenHash = sha256(token);
    return { token, tokenHash, sessionId };
  }

  /**
   * Hash an arbitrary token string for database lookup.
   * Returns `null` for obviously malformed inputs (missing `.` separator).
   */
  private hashToken(token: string): string | null {
    if (!/^[A-Za-z0-9_-]{16}\.[a-f0-9]{64}$/.test(token)) {
      return null;
    }
    return sha256(token);
  }

  private findSessionByHash(tokenHash: string): Promise<SessionLookup | null> {
    return this.prisma.authSession.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        revokedAt: true,
      },
    });
  }
}
