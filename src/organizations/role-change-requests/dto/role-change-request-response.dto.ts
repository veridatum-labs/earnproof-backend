import { ApiProperty } from "@nestjs/swagger";
import { OrganizationMemberRole, RoleChangeRequestStatus } from "@prisma/client";

export class RoleChangeApprovalRecordDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  approverId!: string;

  @ApiProperty({ nullable: true })
  reason!: string | null;

  @ApiProperty({ format: "date-time" })
  createdAt!: string;
}

export class RoleChangeRequestResponseDto {
  @ApiProperty()
  id!: string;

  @ApiProperty()
  organizationId!: string;

  @ApiProperty()
  requesterId!: string;

  @ApiProperty()
  targetUserId!: string;

  @ApiProperty()
  targetMemberId!: string;

  @ApiProperty({ enum: ["OWNER", "ADMIN", "MEMBER", "VIEWER"] })
  oldRole!: OrganizationMemberRole;

  @ApiProperty({ enum: ["OWNER", "ADMIN", "MEMBER", "VIEWER"] })
  proposedRole!: OrganizationMemberRole;

  @ApiProperty()
  justification!: string;

  @ApiProperty({ enum: ["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"] })
  status!: RoleChangeRequestStatus;

  @ApiProperty()
  expectedMemberRevision!: number;

  @ApiProperty()
  policyVersion!: number;

  @ApiProperty()
  requiredApprovals!: number;

  @ApiProperty()
  currentApprovalsCount!: number;

  @ApiProperty({ format: "date-time" })
  expiresAt!: string;

  @ApiProperty({ nullable: true })
  decidedById!: string | null;

  @ApiProperty({ nullable: true, format: "date-time" })
  decidedAt!: string | null;

  @ApiProperty({ nullable: true })
  decisionReason!: string | null;

  @ApiProperty({ nullable: true, format: "date-time" })
  appliedAt!: string | null;

  @ApiProperty({ format: "date-time" })
  createdAt!: string;

  @ApiProperty({ format: "date-time" })
  updatedAt!: string;

  @ApiProperty({ type: RoleChangeApprovalRecordDto, isArray: true })
  approvals!: RoleChangeApprovalRecordDto[];
}
