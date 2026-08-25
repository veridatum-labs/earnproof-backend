import { Module } from "@nestj/common";
import { ContractAnchoringService } from "../proofs/contract-anchoring.service";
import { AnchoringReconcilerService } from "./anchoring-reconciler.service";
import { AnchoringWorkerService } from "./anchoring-worker.service";
import { PaymentSyncService } from "../payments/payment-sync.service";
import { PaymentSyncWorkerService } from "./payment-sync-worker.service";

@Module({
  providers: [
    ContractAnchoringService,
    AnchoringWorkerService,
    Anchoring ReconcilerService,
    PaymentSyncService,
    PaymentSyncWorkerService,
  ],
  exports: [AnchoringWorkerService, AnchoringReconcilerService, PaymentSyncWorkerService],
})
export class JobsModule {}