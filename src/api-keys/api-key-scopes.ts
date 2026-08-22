/**
 * All valid API key scope strings.
 *
 * Scopes follow the pattern `<resource>:<action>` and are enforced by
 * RequireScopes + ApiKeyGuard. A key must carry every scope that a protected
 * endpoint declares – there is no implicit wildcard.
 */
export const API_KEY_SCOPES = [
  "proofs:read",
  "proofs:write",
  "payments:read",
  "payments:write",
  "api-keys:read",
  "api-keys:write",
] as const;

export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];
