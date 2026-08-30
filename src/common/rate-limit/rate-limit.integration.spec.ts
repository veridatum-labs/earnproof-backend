import { Controller, Get, INestApplication } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { Test } from "@nestjs/testing";
import * as request from "supertest";
import { Throttle, SkipThrottle } from "@nestjs/throttler";
import { RateLimitModule } from "./rate-limit.module";
import { AuthTokenService } from "../../auth/auth-token.service";
import { DatabaseModule } from "../../database/database.module";
import { PrismaService } from "../../database/prisma.service";
import { configuration } from "../../config/configuration";

// A minimal controller standing in for the real proofs/payments/health
// controllers, exercising the same decorator combinations they use — this
// proves the wiring in RateLimitModule + RoleAwareThrottlerGuard end-to-end
// (real ThrottlerStorageService, real HTTP requests) rather than re-testing
// the guard's internal logic, which is already covered by
// rate-limit.guard.spec.ts.
@Controller("test")
class TestController {
  @Get("default")
  defaultTier() {
    return { ok: true };
  }

  @SkipThrottle({ default: true, verification: true })
  @Throttle({ strict: {} })
  @Get("strict")
  strictTier() {
    return { ok: true };
  }

  // Mirrors health.controller.ts's real exemption: bare @SkipThrottle()
  // defaults to `{ default: true }` ONLY (see @nestjs/throttler's own
  // SkipThrottle implementation) — every named tier must be listed
  // explicitly for a route to be fully exempt from all of them.
  @SkipThrottle({ default: true, strict: true, verification: true })
  @Get("health")
  health() {
    return { ok: true };
  }
}

describe("Rate limiting (#112) — integration", () => {
  let app: INestApplication;
  let authTokenService: AuthTokenService;

  beforeAll(async () => {
    process.env.RATE_LIMIT_STRICT_LIMIT = "2";
    process.env.RATE_LIMIT_STRICT_TTL_MS = "60000";
    process.env.RATE_LIMIT_DEFAULT_LIMIT = "3";
    process.env.RATE_LIMIT_DEFAULT_TTL_MS = "60000";
    process.env.RATE_LIMIT_AUTHENTICATED_MULTIPLIER = "3";
    process.env.SESSION_SECRET = "test_secret_for_rate_limit_integration";

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, load: [configuration] }),
        DatabaseModule,
        RateLimitModule,
      ],
      controllers: [TestController],
    })
      // RateLimitModule imports AuthModule (for AuthTokenService), which also
      // declares AuthController/AuthService — pulling in PrismaService
      // transitively via the global DatabaseModule. This test never touches
      // the database, so a stub avoids requiring a real Postgres connection
      // just to exercise rate limiting.
      .overrideProvider(PrismaService)
      .useValue({})
      .compile();

    app = moduleRef.createNestApplication();
    authTokenService = moduleRef.get(AuthTokenService);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.RATE_LIMIT_STRICT_LIMIT;
    delete process.env.RATE_LIMIT_STRICT_TTL_MS;
    delete process.env.RATE_LIMIT_DEFAULT_LIMIT;
    delete process.env.RATE_LIMIT_DEFAULT_TTL_MS;
    delete process.env.RATE_LIMIT_AUTHENTICATED_MULTIPLIER;
    delete process.env.SESSION_SECRET;
  });

  it("includes X-RateLimit-* headers on a normal response", async () => {
    const res = await request(app.getHttpServer()).get("/test/default").expect(200);

    expect(res.headers["x-ratelimit-limit"]).toBe("3");
    expect(res.headers["x-ratelimit-remaining"]).toBeDefined();
    expect(res.headers["x-ratelimit-reset"]).toBeDefined();
  });

  it("rejects with 429 and a Retry-After header once the strict threshold is exceeded", async () => {
    const agent = request.agent(app.getHttpServer());

    // limit is 2 for the strict tier in this test's env config. Non-default
    // named throttlers get a suffixed header, e.g. "Retry-After-strict" —
    // see @nestjs/throttler's getThrottlerSuffix in throttler.guard.js.
    await agent.get("/test/strict").expect(200);
    await agent.get("/test/strict").expect(200);
    const blocked = await agent.get("/test/strict").expect(429);

    expect(blocked.headers["retry-after-strict"]).toBeDefined();
    expect(Number(blocked.headers["retry-after-strict"])).toBeGreaterThan(0);
  });

  it("never rate-limits a route marked @SkipThrottle() regardless of volume", async () => {
    const agent = request.agent(app.getHttpServer());

    for (let i = 0; i < 10; i++) {
      await agent.get("/test/health").expect(200);
    }
  });

  it("gives an authenticated caller a higher effective limit than an anonymous one", async () => {
    const token = authTokenService.sign({
      id: "integration-test-user",
      walletAddress: "G".padEnd(56, "A"),
      walletHash: "sha256:integration",
      role: "WORKER",
    });

    // Anonymous default limit is 3; authenticated multiplier is 3x = 9.
    // Use a route-distinct agent (separate tracker key: IP is shared, but
    // the guard tracks authenticated callers by user id) so this is
    // independent of the anonymous-tier test above.
    const agent = request.agent(app.getHttpServer());
    for (let i = 0; i < 5; i++) {
      await agent
        .get("/test/default")
        .set("Authorization", `Bearer ${token}`)
        .expect(200);
    }
  });
});
