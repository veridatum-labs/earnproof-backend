import { SetMetadata } from "@nestjs/common";
import { ApiKeyScope } from "../../api-keys/api-key-scopes";

export const SCOPES_KEY = "requiredScopes";

/**
 * Marks an endpoint as requiring API-key authentication with specific scopes.
 * Must be used together with ApiKeyGuard.
 *
 * @example
 *   @RequireScopes("proofs:read")
 *   @UseGuards(ApiKeyGuard)
 *   @Get("proofs")
 */
export const RequireScopes = (...scopes: ApiKeyScope[]) =>
  SetMetadata(SCOPES_KEY, scopes);
