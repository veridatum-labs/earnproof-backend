-- Issue #278: dual-control approval for privileged role changes.
-- Additive only. Persists role change requests with requester, target, old and proposed role,
-- justification, expiry, and decision.

-- CreateEnum
CREATE TYPE "RoleChangeRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED');

-- AlterEnum
ALTER TYPE "SecurityNotificationType" ADD VALUE IF NOT EXISTS 'ROLE_CHANGE_REQUESTED';
ALTER TYPE "SecurityNotificationType" ADD VALUE IF NOT EXISTS 'ROLE_CHANGE_APPROVED';
ALTER TYPE "SecurityNotificationType" ADD VALUE IF NOT EXISTS 'ROLE_CHANGE_REJECTED';

-- AlterTable
ALTER TABLE "OrganizationMember" ADD COLUMN "revision" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "OrganizationRoleApprovalPolicy" ADD COLUMN "requireRecentAuth" BOOLEAN NOT NULL DEFAULT true;

-- CreateTable
CREATE TABLE "OrganizationRoleChangeRequest" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "requesterId" TEXT NOT NULL,
    "targetUserId" TEXT NOT NULL,
    "targetMemberId" TEXT NOT NULL,
    "oldRole" "OrganizationMemberRole" NOT NULL,
    "proposedRole" "OrganizationMemberRole" NOT NULL,
    "justification" VARCHAR(512) NOT NULL,
    "status" "RoleChangeRequestStatus" NOT NULL DEFAULT 'PENDING',
    "expectedMemberRevision" INTEGER NOT NULL DEFAULT 0,
    "policyVersion" INTEGER NOT NULL,
    "requiredApprovals" INTEGER NOT NULL DEFAULT 1,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "decidedById" TEXT,
    "decidedAt" TIMESTAMP(3),
    "decisionReason" VARCHAR(512),
    "appliedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrganizationRoleChangeRequest_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "OrganizationRoleChangeRequest_requiredApprovals_check" CHECK ("requiredApprovals" BETWEEN 1 AND 5)
);

-- CreateTable
CREATE TABLE "OrganizationRoleChangeApproval" (
    "id" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "approverId" TEXT NOT NULL,
    "reason" VARCHAR(512),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrganizationRoleChangeApproval_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "OrganizationRoleChangeRequest_organizationId_status_idx" ON "OrganizationRoleChangeRequest"("organizationId", "status");
CREATE INDEX "OrganizationRoleChangeRequest_targetMemberId_status_idx" ON "OrganizationRoleChangeRequest"("targetMemberId", "status");
CREATE INDEX "OrganizationRoleChangeRequest_requesterId_idx" ON "OrganizationRoleChangeRequest"("requesterId");
CREATE INDEX "OrganizationRoleChangeRequest_expiresAt_idx" ON "OrganizationRoleChangeRequest"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationRoleChangeApproval_requestId_approverId_key" ON "OrganizationRoleChangeApproval"("requestId", "approverId");
CREATE INDEX "OrganizationRoleChangeApproval_requestId_idx" ON "OrganizationRoleChangeApproval"("requestId");

-- AddForeignKey
ALTER TABLE "OrganizationRoleChangeRequest" ADD CONSTRAINT "OrganizationRoleChangeRequest_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OrganizationRoleChangeRequest" ADD CONSTRAINT "OrganizationRoleChangeRequest_requesterId_fkey" FOREIGN KEY ("requesterId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "OrganizationRoleChangeRequest" ADD CONSTRAINT "OrganizationRoleChangeRequest_targetUserId_fkey" FOREIGN KEY ("targetUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "OrganizationRoleChangeRequest" ADD CONSTRAINT "OrganizationRoleChangeRequest_targetMemberId_fkey" FOREIGN KEY ("targetMemberId") REFERENCES "OrganizationMember"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationRoleChangeApproval" ADD CONSTRAINT "OrganizationRoleChangeApproval_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "OrganizationRoleChangeRequest"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "OrganizationRoleChangeApproval" ADD CONSTRAINT "OrganizationRoleChangeApproval_approverId_fkey" FOREIGN KEY ("approverId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
