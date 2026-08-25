import { Injectable, Logger } from "@nestjs/common";
import { Cron, CronExpression } from "@nestjs/schedule";
import { SessionService } from "./session.service";

@Injectable()
export class CleanupJob {
  private readonly logger = new Logger(CleanupJob.name);

  constructor(private readonly sessionService: SessionService) {}

  @Cron(
    process.env.AUTH_SESSION_CLEANUP_CRON ??
      CronExpression.EVERY_DAY_AT_MIDNIGHT,
  )
  async deleteExpiredSessions(): Promise<void> {
    const deleted = await this.sessionService.deleteExpired();
    this.logger.log(`Removed ${deleted} expired authentication session(s)`);
  }
}
