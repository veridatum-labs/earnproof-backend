export type PrivacyRequestType =
  | 'ACCESS'
  | 'CORRECTION'
  | 'RESTRICTION'
  | 'EXPORT'
  | 'DELETION';

export type PrivacyRequestStatus =
  | 'PENDING_VERIFICATION'
  | 'VERIFIED'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'DENIED'
  | 'EXPIRED'
  | 'CANCELLED';

export interface PrivacyRequestRecord {
  id: string;
  userId: string;
  type: PrivacyRequestType;
  status: PrivacyRequestStatus;
  requestedAt: Date;
  dueAt: Date;
  retentionUntil: Date;
  verifiedAt: Date | null;
  completedAt: Date | null;
  evidenceRef: string | null;
  resultDeliveryRef: string | null;
  resolutionReason: string | null;
  ledgerLimitationNote: string;
}

export interface PrivacyRequestStore {
  create(data: Omit<PrivacyRequestRecord, 'id'>): Promise<PrivacyRequestRecord>;
  findById(id: string): Promise<PrivacyRequestRecord | null>;
  listByUserId(userId: string, limit: number): Promise<PrivacyRequestRecord[]>;
  update(id: string, patch: Partial<PrivacyRequestRecord>): Promise<PrivacyRequestRecord>;
}

const ALLOWED_TRANSITIONS: Record<PrivacyRequestStatus, ReadonlySet<PrivacyRequestStatus>> = {
  PENDING_VERIFICATION: new Set(['VERIFIED', 'CANCELLED', 'EXPIRED']),
  VERIFIED: new Set(['IN_PROGRESS', 'DENIED', 'CANCELLED', 'EXPIRED']),
  IN_PROGRESS: new Set(['COMPLETED', 'DENIED', 'EXPIRED']),
  COMPLETED: new Set([]),
  DENIED: new Set([]),
  EXPIRED: new Set([]),
  CANCELLED: new Set([]),
};

const DEFAULT_SLA_DAYS = 30;
const DEFAULT_RETENTION_DAYS = 90;
const MAX_PAGE_LIMIT = 100;

export const IMMUTABLE_LEDGER_LIMITATION =
  'Immutable ledger entries cannot be altered or erased in place; privacy fulfillment updates off-chain personal records, access/export artifacts, and revocation/redaction state.';

export class PrivacyLifecycleService {
  constructor(
    private readonly store: PrivacyRequestStore,
    private readonly now: () => Date = () => new Date()
  ) {}

  async createRequest(
    actorUserId: string,
    type: PrivacyRequestType,
    evidenceRef?: string
  ): Promise<PrivacyRequestRecord> {
    if (!actorUserId) {
      throw new Error('UNAUTHORIZED_ACTOR');
    }

    const requestedAt = this.now();
    const dueAt = new Date(requestedAt.getTime() + DEFAULT_SLA_DAYS * 86_400_000);
    const retentionUntil = new Date(
      requestedAt.getTime() + DEFAULT_RETENTION_DAYS * 86_400_000
    );

    return this.store.create({
      userId: actorUserId,
      type,
      status: 'PENDING_VERIFICATION',
      requestedAt,
      dueAt,
      retentionUntil,
      verifiedAt: null,
      completedAt: null,
      evidenceRef: evidenceRef ?? null,
      resultDeliveryRef: null,
      resolutionReason: null,
      ledgerLimitationNote: IMMUTABLE_LEDGER_LIMITATION,
    });
  }

  async getRequestForUser(actorUserId: string, requestId: string): Promise<PrivacyRequestRecord> {
    const record = await this.store.findById(requestId);
    if (!record || record.userId !== actorUserId) {
      throw new Error('PRIVACY_REQUEST_NOT_FOUND');
    }
    return this.withExpiredIfPastDue(record);
  }

  async listRequestsForUser(
    actorUserId: string,
    limit = 20
  ): Promise<PrivacyRequestRecord[]> {
    const boundedLimit = Math.min(Math.max(limit, 1), MAX_PAGE_LIMIT);
    const items = await this.store.listByUserId(actorUserId, boundedLimit);
    return Promise.all(items.map((item) => this.withExpiredIfPastDue(item)));
  }

  async verifyRequest(actorUserId: string, requestId: string): Promise<PrivacyRequestRecord> {
    const record = await this.getRequestForUser(actorUserId, requestId);
    this.assertTransition(record.status, 'VERIFIED');
    return this.store.update(record.id, {
      status: 'VERIFIED',
      verifiedAt: this.now(),
    });
  }

  async transitionRequest(
    actorUserId: string,
    requestId: string,
    nextStatus: PrivacyRequestStatus,
    details: {
      evidenceRef?: string;
      resultDeliveryRef?: string;
      resolutionReason?: string;
    } = {}
  ): Promise<PrivacyRequestRecord> {
    const record = await this.getRequestForUser(actorUserId, requestId);
    this.assertTransition(record.status, nextStatus);

    if (nextStatus === 'DENIED' && !details.resolutionReason?.trim()) {
      throw new Error('RESOLUTION_REASON_REQUIRED');
    }

    const patch: Partial<PrivacyRequestRecord> = {
      status: nextStatus,
      evidenceRef: details.evidenceRef ?? record.evidenceRef,
      resultDeliveryRef: details.resultDeliveryRef ?? record.resultDeliveryRef,
      resolutionReason: details.resolutionReason ?? record.resolutionReason,
    };

    if (nextStatus === 'COMPLETED') {
      patch.completedAt = this.now();
    }

    return this.store.update(record.id, patch);
  }

  private assertTransition(
    current: PrivacyRequestStatus,
    next: PrivacyRequestStatus
  ): void {
    if (!ALLOWED_TRANSITIONS[current].has(next)) {
      throw new Error(`INVALID_STATE_TRANSITION_${current}_TO_${next}`);
    }
  }

  private async withExpiredIfPastDue(
    record: PrivacyRequestRecord
  ): Promise<PrivacyRequestRecord> {
    const terminal =
      record.status === 'COMPLETED' ||
      record.status === 'DENIED' ||
      record.status === 'CANCELLED' ||
      record.status === 'EXPIRED';

    if (!terminal && this.now().getTime() > record.dueAt.getTime()) {
      return this.store.update(record.id, {
        status: 'EXPIRED',
        resolutionReason: record.resolutionReason ?? 'Request SLA deadline elapsed',
      });
    }
    return record;
  }
}
