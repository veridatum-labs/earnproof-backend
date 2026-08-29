import { Module } from "@nestjs/common";
import { BullModule } from "@nestjs/bull";
import { AuthModule } from "../auth/auth.module";
import { StellarModule } from "../stellar/stellar.module";
import { PaymentsController } from "./payments.controller";
import { PaymentsService } from "./payments.service";
import { PaymentSyncProcessor } from "./payment-sync.processor";

@Module({
  imports: [
    AuthModule,
    StellarModule,
    BullModule.registerQueue({
      name: "payment-sync",
    }),
  ],
  controllers: [PaymentsController],
  providers: [PaymentsService, PaymentSyncProcessor],
})
export class PaymentsModule {}
