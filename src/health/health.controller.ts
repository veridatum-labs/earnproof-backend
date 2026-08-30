import { Controller, Get } from "@nestjs/common";
import { SkipThrottle } from "@nestjs/throttler";
import { PrismaService } from "../database/prisma.service";

// Rate limiting is exempt for internal health checks (#112 acceptance
// criterion) — an orchestrator/load balancer polling this frequently must
// never itself be treated as abuse. `@SkipThrottle()` with NO argument only
// skips the "default" named throttler (it defaults to `{ default: true }`,
// per @nestjs/throttler's own decorator implementation) — every OTHER named
// throttler (here: "strict", "verification") still applies unless also
// listed explicitly. All three tiers must be named for a true full exemption.
@SkipThrottle({ default: true, strict: true, verification: true })
@Controller("health")
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  async getHealth() {
    await this.prisma.$queryRaw`SELECT 1`;

    return {
      status: "ok",
      service: "earnproof-api",
      database: "ok",
      timestamp: new Date().toISOString(),
    };
  }
}
