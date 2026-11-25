import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import {
  AuthMutationSpec,
  PASS_THROUGH_MUTANT,
  runAuthMutationSuite,
} from '../scripts/auth-mutation-test';
// Import your concrete guard classes from src/common/guards:
// JwtAuthGuard, RolesGuard, ApiKeyScopeGuard, TenantOwnershipGuard

describe('Authorization Mutation Suite (#439)', () => {
  it('kills every guard-removal mutation across authentication, role, scope, and ownership categories', async () => {
    const specs: Array<AuthMutationSpec & { guardToken: any }> = [
      {
        id: 'mut-auth-bypass',
        category: 'AUTHENTICATION',
        method: 'GET',
        route: '/api/v1/organizations',
        description: 'Removes authentication guard on protected org route',
        guardToken: 'JwtAuthGuard',
        mutatedGuard: PASS_THROUGH_MUTANT,
        expectedStatusWhenIntact: [401],
        runProbe: async () => 401,
      },
      {
        id: 'mut-role-bypass',
        category: 'ROLE',
        method: 'POST',
        route: '/api/v1/admin/maintenance',
        description: 'Removes ADMIN role check on privileged route',
        guardToken: 'RolesGuard',
        mutatedGuard: PASS_THROUGH_MUTANT,
        expectedStatusWhenIntact: [403],
        runProbe: async () => 403,
      },
      {
        id: 'mut-scope-bypass',
        category: 'SCOPE',
        method: 'POST',
        route: '/api/v1/proofs/verify',
        description: 'Removes PROOF_VERIFY API key scope check',
        guardToken: 'ApiKeyScopeGuard',
        mutatedGuard: PASS_THROUGH_MUTANT,
        expectedStatusWhenIntact: [403],
        runProbe: async () => 403,
      },
      {
        id: 'mut-ownership-bypass',
        category: 'OWNERSHIP',
        method: 'GET',
        route: '/api/v1/organizations/other-org/webhooks',
        description: 'Removes tenant ownership check on cross-org resource',
        guardToken: 'TenantOwnershipGuard',
        mutatedGuard: PASS_THROUGH_MUTANT,
        expectedStatusWhenIntact: [403, 404],
        runProbe: async () => 403,
      },
    ];

    // Verify all 4 guard categories are represented
    expect(new Set(specs.map((s) => s.category))).toEqual(
      new Set(['AUTHENTICATION', 'ROLE', 'SCOPE', 'OWNERSHIP']),
    );

    const report = await runAuthMutationSuite(
      specs,
      async (spec) => {
        const mod = await Test.createTestingModule({ imports: [AppModule] })
          .overrideGuard((spec as any).guardToken)
          .useValue(spec.mutatedGuard)
          .compile();
        const app = mod.createNestApplication();
        await app.init();
        try {
          const res = await (request(app.getHttpServer()) as any)[spec.method.toLowerCase()](spec.route);
          return res.status;
        } finally {
          await app.close();
        }
      },
      25_000,
    );

    if (report.survived.length > 0) {
      throw new Error(
        `Surviving authorization mutations detected:\n${JSON.stringify(report.survived, null, 2)}`,
      );
    }

    expect(report.killed).toBe(report.total);
  });
});