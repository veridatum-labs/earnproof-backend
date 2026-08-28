import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { SessionService } from "./session.service";
import { AuthGuard } from "../common/guards/auth.guard";
import { CleanupJob } from "./cleanup.job";
import { AuthAuditService } from "./auth-audit.service";
import { AuthRateLimiterService } from "./auth-rate-limiter.service";

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    SessionService,
    AuthAuditService,
    AuthRateLimiterService,
    AuthGuard,
    CleanupJob,
  ],
  exports: [SessionService, AuthGuard, AuthAuditService],
})
export class AuthModule {}
