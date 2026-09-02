import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Reflector } from "@nestjs/core";
import {
  ThrottlerGuard,
  ThrottlerModuleOptions,
  ThrottlerRequest,
  ThrottlerStorage,
} from "@nestjs/throttler";
import { Request } from "express";
import { AuthTokenService } from "../../auth/auth-token.service";
import { AuthTokenPayload } from "../../auth/auth.types";

/**
 * Rate limiting (#112): a role-aware `ThrottlerGuard`.
 *
 * `@nestjs/throttler`'s config resolves a fixed limit per named throttler at
 * startup — it has no built-in concept of "give authenticated callers more."
 * This guard multiplies whichever named throttler's limit is in effect by
 * `rateLimit.authenticatedMultiplier` (from configuration.ts) when the
 * request carries a VALID bearer token — anonymous (or invalid-token)
 * callers get the throttler's configured limit unchanged.
 *
 * This is registered as a GLOBAL guard (see rate-limit.module.ts), which in
 * NestJS runs BEFORE any route-level `@UseGuards(AuthGuard)` — so
 * `request.user` is NOT yet populated when this guard runs, even on routes
 * that also apply `AuthGuard`. Rather than depend on guard ordering (fragile
 * — it would silently break the multiplier the day someone reorders guards),
 * this guard independently best-effort-verifies the bearer token itself via
 * `AuthTokenService.tryVerify` (non-throwing) purely to decide the tier. It
 * never rejects a request for a missing/invalid token — that enforcement
 * stays exactly where it is today, in each route's own `AuthGuard`.
 */
@Injectable()
export class RoleAwareThrottlerGuard extends ThrottlerGuard {
  private readonly authenticatedMultiplier: number;

  constructor(
    options: ThrottlerModuleOptions,
    storageService: ThrottlerStorage,
    reflector: Reflector,
    configService: ConfigService,
    private readonly authTokenService: AuthTokenService,
  ) {
    super(options, storageService, reflector);
    this.authenticatedMultiplier = configService.get<number>(
      "rateLimit.authenticatedMultiplier",
      1,
    );
  }

  /** The verified payload for this request's bearer token, or `undefined` —
   * for a missing header, a malformed/invalid/expired token, or no header
   * at all. Never throws. */
  private authenticatedUser(request: Request): AuthTokenPayload | undefined {
    const header = request.headers.authorization;
    if (!header?.startsWith("Bearer ")) return undefined;
    return this.authTokenService.tryVerify(header.slice("Bearer ".length));
  }

  protected async getTracker(req: Record<string, unknown>): Promise<string> {
    const request = req as unknown as Request;
    const user = this.authenticatedUser(request);
    // Track authenticated callers by user id (stable across IPs — a mobile
    // client switching networks shouldn't reset its budget), anonymous
    // callers by IP (the only identity available for them).
    return user ? `user:${user.id}` : `ip:${request.ip}`;
  }

  protected async handleRequest(
    requestProps: ThrottlerRequest,
  ): Promise<boolean> {
    const request = requestProps.context.switchToHttp().getRequest<Request>();
    const isAuthenticated = Boolean(this.authenticatedUser(request));

    if (!isAuthenticated || this.authenticatedMultiplier <= 1) {
      return super.handleRequest(requestProps);
    }

    // Scale the limit up for this call only — the throttler's own config
    // (and therefore its storage key naming) is untouched, so anonymous and
    // authenticated buckets for the "same" tracker key never collide.
    const scaled: ThrottlerRequest = {
      ...requestProps,
      limit: Math.floor(requestProps.limit * this.authenticatedMultiplier),
    };
    return super.handleRequest(scaled);
  }

  // `Retry-After` and the `X-RateLimit-*` headers are already set correctly
  // by the base ThrottlerGuard.handleRequest (see @nestjs/throttler's
  // `setHeaders` option, enabled in RateLimitModule) — no override needed
  // here. An earlier version of this guard duplicated `Retry-After` with an
  // incorrect value (the throttler's window TTL, not the actual remaining
  // block time); removed rather than left as dead/wrong code.
}
