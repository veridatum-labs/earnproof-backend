export interface SessionPolicyConfig {
  idleTimeoutSeconds: number;
  maxSessionDurationSeconds: number;
  extensionWindowSeconds: number;
  maxExtensionsPerSession: number;
}

export interface SessionRecord {
  id: string;
  userId: string;
  organizationId: string | null;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  extensionCount: number;
  revokedAt: Date | null;
  revokedReason: string | null;
}

export interface SessionAuditEntry {
  sessionId: string;
  userId: string;
  action: 'HEARTBEAT' | 'EXTEND' | 'REVOKE' | 'REJECT';
  outcome: 'ALLOWED' | 'DENIED';
  reason?: string;
  occurredAt: Date;
}

export interface SessionStore {
  findById(sessionId: string): Promise<SessionRecord | null>;
  save(session: SessionRecord): Promise<SessionRecord>;
  recordAudit(entry: SessionAuditEntry): Promise<void>;
}

export const DEFAULT_SESSION_POLICY: SessionPolicyConfig = {
  idleTimeoutSeconds: 900,
  maxSessionDurationSeconds: 28_800,
  extensionWindowSeconds: 900,
  maxExtensionsPerSession: 3,
};

export class SessionPolicyService {
  constructor(
    private readonly store: SessionStore,
    private readonly now: () => Date = () => new Date()
  ) {}

  isSessionExpired(
    session: SessionRecord,
    policy: SessionPolicyConfig,
    at: Date = this.now()
  ): boolean {
    if (session.revokedAt !== null) {
      return true;
    }
    const ts = at.getTime();
    if (ts >= session.expiresAt.getTime()) {
      return true;
    }
    const idleMs = policy.idleTimeoutSeconds * 1000;
    return ts - session.lastActivityAt.getTime() >= idleMs;
  }

  async recordActivityHeartbeat(
    sessionId: string,
    actorUserId: string,
    policy: SessionPolicyConfig = DEFAULT_SESSION_POLICY
  ): Promise<{ active: boolean; expiresAt: Date }> {
    const currentTime = this.now();
    const session = await this.store.findById(sessionId);

    if (!session || session.userId !== actorUserId) {
      throw new Error('SESSION_NOT_FOUND');
    }

    if (this.isSessionExpired(session, policy, currentTime)) {
      await this.store.recordAudit({
        sessionId: session.id,
        userId: session.userId,
        action: 'HEARTBEAT',
        outcome: 'DENIED',
        reason: 'SESSION_EXPIRED_OR_REVOKED',
        occurredAt: currentTime,
      });
      return { active: false, expiresAt: session.expiresAt };
    }

    const updated: SessionRecord = {
      ...session,
      lastActivityAt: currentTime,
    };
    await this.store.save(updated);
    await this.store.recordAudit({
      sessionId: session.id,
      userId: session.userId,
      action: 'HEARTBEAT',
      outcome: 'ALLOWED',
      occurredAt: currentTime,
    });

    return { active: true, expiresAt: updated.expiresAt };
  }

  async extendSession(
    sessionId: string,
    actorUserId: string,
    policy: SessionPolicyConfig = DEFAULT_SESSION_POLICY
  ): Promise<SessionRecord> {
    const currentTime = this.now();
    const session = await this.store.findById(sessionId);

    if (!session || session.userId !== actorUserId) {
      throw new Error('SESSION_NOT_FOUND');
    }

    if (this.isSessionExpired(session, policy, currentTime)) {
      await this.store.recordAudit({
        sessionId: session.id,
        userId: session.userId,
        action: 'EXTEND',
        outcome: 'DENIED',
        reason: 'EXPIRED_OR_REVOKED_CANNOT_EXTEND',
        occurredAt: currentTime,
      });
      throw new Error('SESSION_EXPIRED_OR_REVOKED');
    }

    if (session.extensionCount >= policy.maxExtensionsPerSession) {
      await this.store.recordAudit({
        sessionId: session.id,
        userId: session.userId,
        action: 'EXTEND',
        outcome: 'DENIED',
        reason: 'MAX_EXTENSIONS_REACHED',
        occurredAt: currentTime,
      });
      throw new Error('MAX_EXTENSIONS_REACHED');
    }

    const hardCapMs =
      session.createdAt.getTime() + policy.maxSessionDurationSeconds * 1000;
    const candidateExpiryMs = Math.min(
      currentTime.getTime() + policy.extensionWindowSeconds * 1000,
      hardCapMs
    );

    if (candidateExpiryMs <= session.expiresAt.getTime()) {
      await this.store.recordAudit({
        sessionId: session.id,
        userId: session.userId,
        action: 'EXTEND',
        outcome: 'DENIED',
        reason: 'MAX_SESSION_DURATION_REACHED',
        occurredAt: currentTime,
      });
      throw new Error('MAX_SESSION_DURATION_REACHED');
    }

    const updated: SessionRecord = {
      ...session,
      lastActivityAt: currentTime,
      expiresAt: new Date(candidateExpiryMs),
      extensionCount: session.extensionCount + 1,
    };

    const saved = await this.store.save(updated);
    await this.store.recordAudit({
      sessionId: session.id,
      userId: session.userId,
      action: 'EXTEND',
      outcome: 'ALLOWED',
      occurredAt: currentTime,
    });
    return saved;
  }

  async revokeSession(
    sessionId: string,
    actorUserId: string,
    reason: string
  ): Promise<SessionRecord> {
    const currentTime = this.now();
    const session = await this.store.findById(sessionId);
    if (!session || session.userId !== actorUserId) {
      throw new Error('SESSION_NOT_FOUND');
    }

    const updated: SessionRecord = {
      ...session,
      revokedAt: session.revokedAt ?? currentTime,
      revokedReason: reason,
    };
    const saved = await this.store.save(updated);
    await this.store.recordAudit({
      sessionId: session.id,
      userId: session.userId,
      action: 'REVOKE',
      outcome: 'ALLOWED',
      reason,
      occurredAt: currentTime,
    });
    return saved;
  }
}
