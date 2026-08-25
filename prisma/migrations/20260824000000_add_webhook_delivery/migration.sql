-- AlterTable: add secretEncrypted column to Webhook
ALTER TABLE "Webhook" ADD COLUMN "secretEncrypted" TEXT NOT NULL DEFAULT '';

-- Remove the temporary default so future rows must supply the value
ALTER TABLE "Webhook" ALTER COLUMN "secretEncrypted" DROP DEFAULT;

-- CreateTable
CREATE TABLE "WebhookDelivery" (
    "id"                   TEXT NOT NULL,
    "webhookId"             TEXT NOT NULL,
    "deliveryId"            TEXT NOT NULL,
    "eventType"             TEXT NOT NULL,
    "payload"               JSONB NOT NULL,
    "attemptCount"          INTEGER NOT NULL DEFAULT 0,
    "lastAttemptAt"         TIMESTAMP(3),
    "nextRetryAt"           TIMESTAMP(3),
    "exhaustedAt"           TIMESTAMP(3),
    "latestResponseStatus"  INTEGER,
    "latestResponseBody"    TEXT,
    "replayedById"          TEXT,
    "replayedAt"            TIMESTAMP(3),
    "createdAt"             TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebhookDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WebhookDelivery_deliveryId_key" ON "WebhookDelivery"("deliveryId");
CREATE INDEX "WebhookDelivery_webhookId_createdAt_idx" ON "WebhookDelivery"("webhookId", "createdAt");
CREATE INDEX "WebhookDelivery_nextRetryAt_idx" ON "WebhookDelivery"("nextRetryAt");
CREATE INDEX "WebhookDelivery_exhaustedAt_idx" ON "WebhookDelivery"("exhaustedAt");

-- AddForeignKey
ALTER TABLE "WebhookDelivery" ADD CONSTRAINT "WebhookDelivery_webhookId_fkey"
    FOREIGN KEY ("webhookId") REFERENCES "Webhook"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
