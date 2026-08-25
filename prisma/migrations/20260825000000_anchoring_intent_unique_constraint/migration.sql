-- Drop the old non-unique indexes that allowed concurrent claims
DROP INDEX "AnchoringIntent_status_nextRetryAt_idx";
DROP INDEX "AnchoringIntent_proofId_operation_idx";

-- Create new partial unique constraint to prevent double-claim:
-- Only one PROCESSING or CONFIRMED intent per (proofId, operation) pair.
-- This enforces that the same operation cannot be claimed/executed twice for a proof.
CREATE UNIQUE INDEX "AnchoringIntent_proofId_operation_unique_claim_idx" 
  ON "AnchoringIntent"("proofId", "operation") 
  WHERE "status" IN ('PROCESSING', 'CONFIRMED');

-- Create supporting indexes for query performance
CREATE INDEX "AnchoringIntent_nextRetryAt_idx" ON "AnchoringIntent"("nextRetryAt");
CREATE INDEX "AnchoringIntent_proofId_idx" ON "AnchoringIntent"("proofId");
