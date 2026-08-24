import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { WebhooksModule } from "../webhooks/webhooks.module";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { ProofsController } from "./proofs.controller";
import { ProofsService } from "./proofs.service";

@Module({
  imports: [AuthModule, WebhooksModule],
  controllers: [ProofsController],
  providers: [ContractAnchoringService, ProofsService],
})
export class ProofsModule {}
