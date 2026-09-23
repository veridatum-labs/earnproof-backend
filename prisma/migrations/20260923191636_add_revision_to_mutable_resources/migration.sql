-- Add revision field to Organization
ALTER TABLE "Organization" ADD COLUMN "revision" INTEGER NOT NULL DEFAULT 1;

-- Add revision field to Issuer
ALTER TABLE "Issuer" ADD COLUMN "revision" INTEGER NOT NULL DEFAULT 1;

-- Add revision field to TrustedSource
ALTER TABLE "TrustedSource" ADD COLUMN "revision" INTEGER NOT NULL DEFAULT 1;

-- Add revision field to Webhook
ALTER TABLE "Webhook" ADD COLUMN "revision" INTEGER NOT NULL DEFAULT 1;
