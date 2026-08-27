import { Module } from "@nestj/common";
import { ContractAnchoringService } from "../proofs/contract-anchoring.service";
import { AnchoringReconcilerService } from "./anchoring-reconciler.service";
import { AnchoringWorkerService } from "./anchoring-worker.service";
import { PaymentSyncService } from "../payments/payment-sync.service";
import { PaymentSyncWorkerService } from "./payment-sync-worker.service";
import { RetentionCleanupService } from "./retention/retention-cleanup.service";
import { RetentionJob } from "./retention/retention.job";

@Module({
  providers: [
    ContractAnchoringService,
    AnchoringWorkerService,
    AnchoringReconcilerService,
    PaymentSyncService,
    PaymentSyncWorkerService,
    RetentionCleanupService,
    RetentionJob,
  ],
  exports: [
    AnchoringWorkerService,
    AnchoringReconcilerService,
    PaymentSyncWorkerService,
    RetentionCleanupService,
  ],
})
export class JobsModule {}