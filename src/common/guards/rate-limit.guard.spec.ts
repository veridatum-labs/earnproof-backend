import { ConfigService } from "@nestjs/config";
import { ExecutionContext } from "@nestjs/common";
import { ThrottlerModuleOptions, ThrottlerRequest, ThrottlerStorage } from "@nestjs/throttler";
import { Reflector } from "@nestjs/core";
import { Request } from "express";
import { RoleAwareThrottlerGuard } from "./rate-limit.guard";
import { AuthTokenService } from "../../auth/auth-token.service";

const THROTTLER_OPTIONS: ThrottlerModuleOptions = {
  throttlers: [{ name: "default", ttl: 60_000, limit: 100 }],
};

function fakeStorage(): ThrottlerStorage {
  return {
    increment: jest.fn().mockResolvedValue({
      totalHits: 1,
      timeToExpire: 60,
      isBlocked: false,
      timeToBlockExpire: 0,
    }),
  } as unknown as ThrottlerStorage;
}

function contextWithRequest(request: Partial<Request>): ExecutionContext {
  const fullRequest = { headers: {}, ip: "127.0.0.1", ...request } as Request;
  return {
    switchToHttp: () => ({
      getRequest: () => fullRequest,
      getResponse: () => ({ header: jest.fn() }),
    }),
    getHandler: () => ({}) as never,
    getClass: () => ({}) as never,
  } as unknown as ExecutionContext;
}

async function buildGuard(authenticatedMultiplier: number, tryVerifyResult?: { id: string }) {
  const configService = {
    get: (_key: string, fallback?: unknown) => authenticatedMultiplier ?? fallback,
  } as unknown as ConfigService;
  const authTokenService = {
    tryVerify: jest.fn().mockReturnValue(tryVerifyResult),
  } as unknown as AuthTokenService;
  const storage = fakeStorage();

  const guard = new RoleAwareThrottlerGuard(
    THROTTLER_OPTIONS,
    storage,
    new Reflector(),
    configService,
    authTokenService,
  );
  // The base ThrottlerGuard resolves its `commonOptions` (setHeaders, etc.)
  // in onModuleInit — handleRequest() reads from it, so tests must trigger
  // that lifecycle hook just like Nest's DI container would.
  await (guard as any).onModuleInit();
  return { guard, authTokenService, storage };
}

describe("RoleAwareThrottlerGuard", () => {
  describe("getTracker", () => {
    it("tracks by user id when the bearer token is valid", async () => {
      const { guard } = await buildGuard(3, { id: "user-42" });
      const request = {
        headers: { authorization: "Bearer sometoken" },
        ip: "1.2.3.4",
      };
      const tracker = await (guard as any).getTracker(request);
      expect(tracker).toBe("user:user-42");
    });

    it("tracks by IP when there is no authorization header", async () => {
      const { guard } = await buildGuard(3, undefined);
      const request = { headers: {}, ip: "1.2.3.4" };
      const tracker = await (guard as any).getTracker(request);
      expect(tracker).toBe("ip:1.2.3.4");
    });

    it("tracks by IP when the bearer token fails verification", async () => {
      const { guard } = await buildGuard(3, undefined);
      const request = {
        headers: { authorization: "Bearer garbage" },
        ip: "1.2.3.4",
      };
      const tracker = await (guard as any).getTracker(request);
      expect(tracker).toBe("ip:1.2.3.4");
    });

    it("tracks by IP when the authorization header is not a Bearer token", async () => {
      const { guard, authTokenService } = await buildGuard(3, { id: "user-42" });
      const request = {
        headers: { authorization: "Basic dXNlcjpwYXNz" },
        ip: "1.2.3.4",
      };
      const tracker = await (guard as any).getTracker(request);
      expect(tracker).toBe("ip:1.2.3.4");
      expect(authTokenService.tryVerify).not.toHaveBeenCalled();
    });
  });

  describe("handleRequest", () => {
    function requestProps(context: ExecutionContext): ThrottlerRequest {
      return {
        context,
        limit: 10,
        ttl: 60_000,
        throttler: { name: "default", limit: 10, ttl: 60_000 },
        blockDuration: 60_000,
        getTracker: async () => "ip:1.2.3.4",
        generateKey: () => "key",
      };
    }

    // Asserting against `storageService.increment`'s `limit` argument (rather
    // than spying on the inherited `handleRequest`) exercises the guard
    // through the base class's real implementation end-to-end, including the
    // `onModuleInit`-derived `commonOptions` the base class depends on.
    it("does not scale the limit for an anonymous (unauthenticated) request", async () => {
      const { guard, storage } = await buildGuard(3, undefined);
      const context = contextWithRequest({ headers: {} });

      await guard["handleRequest"](requestProps(context));

      expect(storage.increment).toHaveBeenCalledWith(
        expect.any(String),
        60_000,
        10,
        60_000,
        "default",
      );
    });

    it("scales the limit by the configured multiplier for an authenticated request", async () => {
      const { guard, storage } = await buildGuard(3, { id: "user-42" });
      const context = contextWithRequest({
        headers: { authorization: "Bearer validtoken" },
      });

      await guard["handleRequest"](requestProps(context));

      expect(storage.increment).toHaveBeenCalledWith(
        expect.any(String),
        60_000,
        30, // 10 * 3
        60_000,
        "default",
      );
    });

    it("does not scale the limit when the multiplier is 1 (disabled), even if authenticated", async () => {
      const { guard, storage } = await buildGuard(1, { id: "user-42" });
      const context = contextWithRequest({
        headers: { authorization: "Bearer validtoken" },
      });

      await guard["handleRequest"](requestProps(context));

      expect(storage.increment).toHaveBeenCalledWith(
        expect.any(String),
        60_000,
        10,
        60_000,
        "default",
      );
    });

    it("floors a fractional scaled limit rather than exceeding the intended budget", async () => {
      const { guard, storage } = await buildGuard(1.5, { id: "user-42" });
      const context = contextWithRequest({
        headers: { authorization: "Bearer validtoken" },
      });

      await guard["handleRequest"](requestProps(context));

      expect(storage.increment).toHaveBeenCalledWith(
        expect.any(String),
        60_000,
        15, // floor(10 * 1.5)
        60_000,
        "default",
      );
    });
  });
});
