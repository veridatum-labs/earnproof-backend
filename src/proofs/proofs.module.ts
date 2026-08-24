import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { ContractAnchoringService } from "./contract-anchoring.service";
import { ProofsController } from "./proofs.controller";
import { ProofsService } from "./proofs.service";

@Module({
  imports: [AuthModule],
  controllers: [ProofsController],
  providers: [ContractAnchoringService, ProofsService],
  exports: [ContractAnchoringService],
})
export class ProofsModule {}
