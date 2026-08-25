import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { ScheduleModule } from "@nestjs/schedule";
import { AuditModule } from "./audit/audit.module";
import { ApiKeysModule } from "./api-keys/api-keys.module";
import { AuthModule } from "./auth/auth.module";
import { configuration } from "./config/configuration";
import { validateEnv } from "./config/env.validation";
import { DatabaseModule } from "./database/database.module";
import { HealthModule } from "./health/health.module";
import { JobsModule } from "./jobs/jobs.module";
import { IssuersModule } from "./issuers/issuers.module";
import { OrganizationsModule } from "./organizations/organizations.module";
import { PaymentsModule } from "./payments/payments.module";
import { ProofsModule } from "./proofs/proofs.module";
import { TrustedSourcesModule } from "./trusted-sources/trusted-sources.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate: validateEnv,
    }),
    ScheduleModule.forRoot(),
    DatabaseModule,
    AuditModule,
    ApiKeysModule,
    AuthModule,
    HealthModule,
    OrganizationsModule,
    IssuersModule,
    PaymentsModule,
    ProofsModule,
    TrustedSourcesModule,
    JobsModule,
  ],
})
export class AppModule {}
