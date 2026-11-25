import { CanActivate, ExecutionContext } from '@nestjs/common';

export type GuardCategory = 'AUTHENTICATION' | 'ROLE' | 'SCOPE' | 'OWNERSHIP';

export interface AuthMutationSpec {
  id: string;
  category: GuardCategory;
  route: string;
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  description: string;
  /** Mutated guard that simulates an accidental refactor removing the check */
  mutatedGuard: CanActivate;
  /** Security test probe that MUST fail (i.e. get 2xx instead of 401/403) when the guard is mutated */
  runProbe: (appUrl: string) => Promise<number>;
  expectedStatusWhenIntact: number[];
}

export const PASS_THROUGH_MUTANT: CanActivate = {
  canActivate: (_ctx: ExecutionContext) => true,
};

export interface MutationReport {
  total: number;
  killed: number;
  survived: Array<{ id: string; category: GuardCategory; route: string; method: string; observedStatus: number }>;
  durationMs: number;
}

export async function runAuthMutationSuite(
  specs: AuthMutationSpec[],
  executeWithMutant: (spec: AuthMutationSpec) => Promise<number>,
  timeoutMs = 30_000,
): Promise<MutationReport> {
  const startedAt = Date.now();
  const survived: MutationReport['survived'] = [];

  for (const spec of specs) {
    if (Date.now() - startedAt > timeoutMs) {
      throw new Error(`Authorization mutation suite exceeded time bound (${timeoutMs}ms)`);
    }

    const observedStatus = await executeWithMutant(spec);

    // If the probe STILL returns 401/403 even with the guard bypassed, or if tests wouldn't notice,
    // verify the probe actually detects the bypass (status diverges from intact 401/403).
    const mutationDetected = !spec.expectedStatusWhenIntact.includes(observedStatus);
    if (!mutationDetected) {
      survived.push({
        id: spec.id,
        category: spec.category,
        route: spec.route,
        method: spec.method,
        observedStatus,
      });
    }
  }

  return {
    total: specs.length,
    killed: specs.length - survived.length,
    survived,
    durationMs: Date.now() - startedAt,
  };
}