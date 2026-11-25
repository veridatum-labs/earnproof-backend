import { PrivacyLifecycleService } from '../../src/privacy/privacyRequest.service';
import {
  DEFAULT_SESSION_POLICY,
  SessionPolicyService,
} from '../../src/sessions/sessionPolicy.service';
import { PermissionSimulationService } from '../../src/permissions/permissionSimulation.service';
import { CommitmentAlgorithmPolicyService } from '../../src/credentials/commitmentAlgorithmPolicy.service';

describe('Privacy, Session, Permission Simulation, and Hash Algorithm Policies', () => {
  test('#402 prevents cross-user discovery and exposes immutable ledger limitation', async () => {
    const items: any[] = [];
    const store = {
      create: async (d: any) => {
        const rec = { ...d, id: `pr_${items.length + 1}` };
        items.push(rec);
        return rec;
      },
      findById: async (id: string) => items.find((x) => x.id === id) ?? null,
      listByUserId: async (uid: string, lim: number) =>
        items.filter((x) => x.userId === uid).slice(0, lim),
      update: async (id: string, patch: any) => {
        const idx = items.findIndex((x) => x.id === id);
        items[idx] = { ...items[idx], ...patch };
        return items[idx];
      },
    };

    const service = new PrivacyLifecycleService(store, () => new Date('2026-11-25T00:00:00Z'));
    const created = await service.createRequest('user_a', 'DELETION');
    expect(created.ledgerLimitationNote).toContain('Immutable ledger');

    await expect(service.getRequestForUser('user_b', created.id)).rejects.toThrow(
      'PRIVACY_REQUEST_NOT_FOUND'
    );
  });

  test('#403 blocks extending expired sessions and does not revive via heartbeat', async () => {
    let clock = new Date('2026-11-25T00:00:00Z');
    const audits: any[] = [];
    let session: any = {
      id: 'sess_1',
      userId: 'user_1',
      organizationId: 'org_1',
      createdAt: clock,
      lastActivityAt: clock,
      expiresAt: new Date(clock.getTime() + 600_000),
      extensionCount: 0,
      revokedAt: null,
      revokedReason: null,
    };

    const store = {
      findById: async () => session,
      save: async (s: any) => {
        session = s;
        return s;
      },
      recordAudit: async (e: any) => {
        audits.push(e);
      },
    };

    const svc = new SessionPolicyService(store, () => clock);
    clock = new Date(clock.getTime() + 901_000);

    const hb = await svc.recordActivityHeartbeat('sess_1', 'user_1', DEFAULT_SESSION_POLICY);
    expect(hb.active).toBe(false);
    await expect(svc.extendSession('sess_1', 'user_1', DEFAULT_SESSION_POLICY)).rejects.toThrow(
      'SESSION_EXPIRED_OR_REVOKED'
    );
    expect(audits.some((a) => a.outcome === 'DENIED')).toBe(true);
  });

  test('#404 simulates permissions non-mutating and fails closed on unknown inputs', () => {
    const sim = new PermissionSimulationService(() => new Date('2026-11-25T00:00:00Z'));
    const result = sim.simulate({
      tenantId: 't1',
      apiKeyTenantId: 't1',
      network: 'mainnet',
      allowedNetworks: ['mainnet'],
      requestedScopes: ['proof:read', 'unknown:scope'],
      knownAllowedScopes: new Set(['proof:read']),
      quotaRemaining: 10,
      policyVersion: 'v2026.11',
    });

    expect(result.effectiveScopes).toEqual(['proof:read']);
    expect(result.denied[0].scope).toBe('unknown:scope');
    expect(result.policyVersion).toBe('v2026.11');
  });

  test('#397 blocks deprecated algorithm on issuance while keeping historical identifiers', async () => {
    let policies = [
      { algorithmId: 'poseidon', version: 'v1', status: 'ACTIVE' as const },
      { algorithmId: 'legacy-sha256', version: 'v0', status: 'DEPRECATED' as const },
    ];
    const svc = new CommitmentAlgorithmPolicyService(
      { loadPolicies: async () => policies },
      60_000,
      100,
      () => 1_795_564_800_000
    );

    await expect(svc.assertIssuable('poseidon', 'v1')).resolves.toMatchObject({
      status: 'ACTIVE',
    });
    await expect(svc.assertIssuable('legacy-sha256', 'v0')).rejects.toThrow(
      'ALGORITHM_NOT_ISSUABLE'
    );
    expect(svc.resolveExistingRecordIdentifier('legacy-sha256', 'v0')).toEqual({
      algorithmId: 'legacy-sha256',
      version: 'v0',
    });
  });
});
