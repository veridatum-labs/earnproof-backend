-- CreateEnum for ApiKeyScope
CREATE TYPE "ApiKeyScope" AS ENUM ('PROOF_READ', 'PROOF_VERIFY', 'PAYMENT_READ', 'PAYMENT_WRITE', 'ORG_READ', 'ORG_ADMIN');

-- AlterTable ApiKey to add new fields
ALTER TABLE "ApiKey" ADD COLUMN "prefix" VARCHAR(8) NOT NULL DEFAULT '',
ADD COLUMN "rotatedAt" TIMESTAMP(3),
ADD COLUMN "revokedAt" TIMESTAMP(3),
ADD COLUMN "lastUsedAt" TIMESTAMP(3);

-- CreateTable ApiKeyScopeAssignment
CREATE TABLE "ApiKeyScopeAssignment" (
    "id" TEXT NOT NULL,
    "apiKeyId" TEXT NOT NULL,
    "scope" "ApiKeyScope" NOT NULL,

    CONSTRAINT "ApiKeyScopeAssignment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ApiKeyScopeAssignment_apiKeyId_scope_key" ON "ApiKeyScopeAssignment"("apiKeyId", "scope");

-- CreateIndex
CREATE INDEX "ApiKeyScopeAssignment_apiKeyId_idx" ON "ApiKeyScopeAssignment"("apiKeyId");

-- CreateIndex
CREATE INDEX "ApiKey_prefix_idx" ON "ApiKey"("prefix");

-- AddForeignKey
ALTER TABLE "ApiKeyScopeAssignment" ADD CONSTRAINT "ApiKeyScopeAssignment_apiKeyId_fkey" FOREIGN KEY ("apiKeyId") REFERENCES "ApiKey"("id") ON DELETE CASCADE ON UPDATE CASCADE;
