import { ApiProperty } from "@nestjs/swagger";
import { OrganizationRole } from "@prisma/client";

export class MembershipResponseDto {
  @ApiProperty({
    description: "Membership record ID",
    example: "clh1234567890123456789012",
  })
  id: string;

  @ApiProperty({
    description: "Organization ID",
    example: "clh1234567890123456789012",
  })
  organizationId: string;

  @ApiProperty({
    description: "User ID",
    example: "clh1234567890123456789012",
  })
  userId: string;

  @ApiProperty({
    description: "User wallet address",
    example: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  })
  walletAddress: string;

  @ApiProperty({
    description: "Member's role in the organization",
    enum: ["OWNER", "ADMIN", "READER"],
  })
  role: OrganizationRole;

  @ApiProperty({
    description: "Membership creation timestamp",
    example: "2026-01-01T12:00:00Z",
  })
  createdAt: Date;

  @ApiProperty({
    description: "Last membership update timestamp",
    example: "2026-01-01T12:00:00Z",
  })
  updatedAt: Date;
}
