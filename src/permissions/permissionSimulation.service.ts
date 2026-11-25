export interface SimulationInput {
  tenantId: string;
  apiKeyTenantId: string;
  network: string;
  allowedNetworks: readonly string[];
  requestedScopes: readonly string[];
  knownAllowedScopes: ReadonlySet<string>;
  quotaRemaining: number;
  policyVersion: string;
}

export interface ScopeSimulationResult {
  scope: string;
  allowed: boolean;
  reasons: string[];
}

export interface PermissionSimulationOutput {
  policyVersion: string;
  tenantId: string;
  network: string;
  effectiveScopes: string[];
  denied: ScopeSimulationResult[];
  evaluatedAt: string;
}

export class PermissionSimulationService {
  constructor(private readonly now: () => Date = () => new Date()) {}

  simulate(input: SimulationInput): PermissionSimulationOutput {
    const policyVersion =
      typeof input.policyVersion === 'string' && input.policyVersion.trim().length > 0
        ? input.policyVersion
        : 'UNKNOWN_POLICY_VERSION';

    const tenantMatch =
      Boolean(input.tenantId) &&
      Boolean(input.apiKeyTenantId) &&
      input.tenantId === input.apiKeyTenantId;

    const networkAllowed =
      Boolean(input.network) &&
      Array.isArray(input.allowedNetworks) &&
      input.allowedNetworks.includes(input.network);

    const quotaAvailable =
      typeof input.quotaRemaining === 'number' &&
      Number.isFinite(input.quotaRemaining) &&
      input.quotaRemaining > 0;

    const scopes = Array.isArray(input.requestedScopes) ? input.requestedScopes : [];
    const effectiveScopes: string[] = [];
    const denied: ScopeSimulationResult[] = [];

    for (const scope of scopes) {
      const reasons: string[] = [];

      if (typeof scope !== 'string' || !input.knownAllowedScopes.has(scope)) {
        reasons.push('UNKNOWN_OR_UNPERMITTED_SCOPE');
      }
      if (!tenantMatch) {
        reasons.push('TENANT_MISMATCH_OR_MISSING');
      }
      if (!networkAllowed) {
        reasons.push('NETWORK_NOT_ALLOWED');
      }
      if (!quotaAvailable) {
        reasons.push('QUOTA_EXHAUSTED_OR_INVALID');
      }
      if (policyVersion === 'UNKNOWN_POLICY_VERSION') {
        reasons.push('INVALID_POLICY_VERSION');
      }

      if (reasons.length === 0) {
        effectiveScopes.push(scope);
      } else {
        denied.push({ scope, allowed: false, reasons });
      }
    }

    return {
      policyVersion,
      tenantId: input.tenantId,
      network: input.network,
      effectiveScopes,
      denied,
      evaluatedAt: this.now().toISOString(),
    };
  }
}
