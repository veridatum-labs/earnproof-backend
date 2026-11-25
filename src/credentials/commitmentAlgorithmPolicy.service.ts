export type AlgorithmLifecycleStatus = 'ACTIVE' | 'DEPRECATED' | 'UNKNOWN';

export interface CommitmentAlgorithmPolicy {
  algorithmId: string;
  version: string;
  status: Exclude<AlgorithmLifecycleStatus, 'UNKNOWN'>;
}

export interface PolicySource {
  loadPolicies(): Promise<CommitmentAlgorithmPolicy[]>;
}

export class CommitmentAlgorithmPolicyService {
  private cache = new Map<string, { policy: CommitmentAlgorithmPolicy; expiresAt: number }>();
  private lastRefreshedAt = 0;

  constructor(
    private readonly source: PolicySource,
    private readonly ttlMs: number = 60_000,
    private readonly maxEntries: number = 256,
    private readonly now: () => number = () => Date.now()
  ) {}

  async reconcilePolicy(): Promise<void> {
    const policies = await this.source.loadPolicies();
    const current = this.now();
    this.cache.clear();

    for (const policy of policies.slice(0, this.maxEntries)) {
      this.cache.set(this.key(policy.algorithmId, policy.version), {
        policy,
        expiresAt: current + this.ttlMs,
      });
    }
    this.lastRefreshedAt = current;
  }

  private async ensureFreshCache(): Promise<void> {
    const current = this.now();
    if (this.lastRefreshedAt === 0 || current - this.lastRefreshedAt >= this.ttlMs) {
      await this.reconcilePolicy();
      return;
    }

    for (const [k, entry] of this.cache.entries()) {
      if (current >= entry.expiresAt) {
        this.cache.delete(k);
      }
    }
  }

  async assertIssuable(algorithmId: string, version: string): Promise<CommitmentAlgorithmPolicy> {
    await this.ensureFreshCache();
    const entry = this.cache.get(this.key(algorithmId, version));
    if (!entry || entry.policy.status !== 'ACTIVE') {
      throw new Error(
        `ALGORITHM_NOT_ISSUABLE:${algorithmId}@${version} (${entry?.policy.status ?? 'UNKNOWN'})`
      );
    }
    return entry.policy;
  }

  resolveExistingRecordIdentifier(
    storedAlgorithmId: string,
    storedVersion: string
  ): { algorithmId: string; version: string } {
    return {
      algorithmId: storedAlgorithmId,
      version: storedVersion,
    };
  }

  private key(algorithmId: string, version: string): string {
    return `${algorithmId}::${version}`;
  }
}
