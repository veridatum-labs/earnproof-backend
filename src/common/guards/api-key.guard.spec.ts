import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ApiKeyPrincipal } from "../../api-keys/api-keys.service";
import { ApiKeyGuard } from "./api-key.guard";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface MockRequest {
  headers: Record<string, string>;
  apiKey?: ApiKeyPrincipal;
}

function buildContext(headers: Record<string, string>): {
  context: ExecutionContext;
  request: MockRequest;
} {
  const request: MockRequest = { headers };
  const context = {
    switchToHttp: () => ({
      getRequest: () => request,
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;

  return { context, request };
}

function buildApiKeysService(principal: object | null = null) {
  return {
    authenticate: jest.fn().mockImplementation(async () => {
      if (!principal) throw new UnauthorizedException("Invalid API key");
      return principal;
    }),
  };
}

function buildReflector(scopes: string[] | undefined) {
  return {
    getAllAndOverride: jest.fn().mockReturnValue(scopes),
  } as unknown as Reflector;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ApiKeyGuard", () => {
  it("activates for a valid key with matching scopes", async () => {
    const principal: ApiKeyPrincipal = {
      keyId: "k1",
      organizationId: "org_1",
      scopes: ["proofs:read"],
    };
    const guard = new ApiKeyGuard(
      buildApiKeysService(principal) as never,
      buildReflector(["proofs:read"]),
    );

    const { context, request } = buildContext({ "x-api-key": "ep_valid_key" });
    await expect(guard.canActivate(context)).resolves.toBe(true);
    // Principal must be attached to request
    expect(request.apiKey).toEqual(principal);
  });

  it("throws UnauthorizedException when x-api-key header is absent", async () => {
    const guard = new ApiKeyGuard(
      buildApiKeysService() as never,
      buildReflector(["proofs:read"]),
    );

    const { context } = buildContext({});
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it("throws UnauthorizedException when service rejects the key", async () => {
    const guard = new ApiKeyGuard(
      buildApiKeysService(null) as never,
      buildReflector(["proofs:read"]),
    );

    const { context } = buildContext({ "x-api-key": "ep_bad" });
    await expect(guard.canActivate(context)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it("throws ForbiddenException when no scopes are declared (closed by default)", async () => {
    const principal: ApiKeyPrincipal = {
      keyId: "k1",
      organizationId: "org_1",
      scopes: ["proofs:read"],
    };
    const guard = new ApiKeyGuard(
      buildApiKeysService(principal) as never,
      buildReflector(undefined), // no @RequireScopes
    );

    const { context } = buildContext({ "x-api-key": "ep_valid" });
    await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
  });

  it("throws ForbiddenException when key lacks a required scope", async () => {
    const principal: ApiKeyPrincipal = {
      keyId: "k1",
      organizationId: "org_1",
      scopes: ["payments:read"],
    };
    const guard = new ApiKeyGuard(
      buildApiKeysService(principal) as never,
      buildReflector(["proofs:read"]),
    );

    const { context } = buildContext({ "x-api-key": "ep_limited_key" });
    await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
  });

  it("requires ALL declared scopes (AND semantics)", async () => {
    const principal: ApiKeyPrincipal = {
      keyId: "k1",
      organizationId: "org_1",
      scopes: ["proofs:read"],
    };
    const guard = new ApiKeyGuard(
      buildApiKeysService(principal) as never,
      buildReflector(["proofs:read", "proofs:write"]),
    );

    const { context } = buildContext({ "x-api-key": "ep_partial_key" });
    await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
  });

  it("activates when key has more scopes than required", async () => {
    const principal: ApiKeyPrincipal = {
      keyId: "k1",
      organizationId: "org_1",
      scopes: ["proofs:read", "proofs:write", "payments:read"],
    };
    const guard = new ApiKeyGuard(
      buildApiKeysService(principal) as never,
      buildReflector(["proofs:read"]),
    );

    const { context } = buildContext({ "x-api-key": "ep_super_key" });
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });
});
