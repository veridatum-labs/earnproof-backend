import { Module } from "@nestjs/common";
import { ScheduleModule } from "@nestjs/schedule";
import { ContractAnchoringService } from "../proofs/contract-anchoring.service";
import { AnchoringReconcilerService } from "./anchoring-reconciler.service";
import { AnchoringWorkerService } from "./anchoring-worker.service";

@Module({
  imports: [ScheduleModule.forRoot()],
  providers: [
    ContractAnchoringService,
    AnchoringWorkerService,
    AnchoringReconcilerService,
  ],
  exports: [AnchoringWorkerService, AnchoringReconcilerService],
})
export class JobsModule {}
