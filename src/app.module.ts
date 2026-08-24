import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AuthModule } from "./auth/auth.module";
import { configuration } from "./config/configuration";
import { validateEnv } from "./config/env.validation";
import { DatabaseModule } from "./database/database.module";
import { HealthModule } from "./health/health.module";
import { JobsModule } from "./jobs/jobs.module";
import { PaymentsModule } from "./payments/payments.module";
import { ProofsModule } from "./proofs/proofs.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate: validateEnv,
    }),
    DatabaseModule,
    AuthModule,
    HealthModule,
    PaymentsModule,
    ProofsModule,
    JobsModule,
  ],
})
export class AppModule {}
