import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { SessionService } from "./session.service";
import { AuthGuard } from "../common/guards/auth.guard";
import { CleanupJob } from "./cleanup.job";

@Module({
  controllers: [AuthController],
  providers: [AuthService, SessionService, AuthGuard, CleanupJob],
  exports: [SessionService, AuthGuard],
})
export class AuthModule {}
