import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { OrganizationMemberRole } from "@prisma/client";
import { IsEnum, IsInt, IsNotEmpty, IsOptional, IsString, MaxLength, Min, MinLength } from "class-validator";
import { ORGANIZATION_ROLES } from "../../role-approval-policy/role-approval-policy.rules";

export class CreateRoleChangeRequestDto {
  @ApiProperty({
    description: "ID of the target organization member whose role should be changed.",
    example: "member_clx123456",
  })
  @IsString()
  @IsNotEmpty()
  memberId!: string;

  @ApiProperty({
    enum: ORGANIZATION_ROLES,
    description: "Proposed organization role.",
    example: "ADMIN",
  })
  @IsEnum(ORGANIZATION_ROLES as readonly string[])
  proposedRole!: OrganizationMemberRole;

  @ApiProperty({
    description: "Business justification for the requested role change.",
    example: "Promoting to organization admin for infrastructure management responsibilities.",
    minLength: 5,
    maxLength: 512,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(5)
  @MaxLength(512)
  justification!: string;

  @ApiPropertyOptional({
    description: "Expected membership revision for optimistic concurrency check.",
    example: 0,
    minimum: 0,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  expectedMemberRevision?: number;
}
