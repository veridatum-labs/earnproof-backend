import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { APP_GUARD } from "@nestjs/core";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { AuthModule } from "./auth/auth.module";
import { configuration } from "./config/configuration";
import { validateEnv } from "./config/env.validation";
import { CredentialsModule } from "./credentials/credentials.module";
import { DatabaseModule } from "./database/database.module";
import { HealthModule } from "./health/health.module";
import { PaymentsModule } from "./payments/payments.module";
import { ProofsModule } from "./proofs/proofs.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate: validateEnv,
    }),
    ThrottlerModule.forRoot([
      {
        name: "default",
        ttl: 60_000, // 1 minute in milliseconds
        limit: 1000, // generous default; per-route overrides tighten this
      },
    ]),
    DatabaseModule,
    AuthModule,
    HealthModule,
    PaymentsModule,
    ProofsModule,
    CredentialsModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
