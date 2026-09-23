import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsEnum } from "class-validator";
import { OrganizationRole } from "@prisma/client";

export class InviteMemberDto {
  @ApiProperty({
    description: "User wallet address to invite as member",
    example: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  })
  @IsString()
  walletAddress: string;

  @ApiProperty({
    description: "Organization role to assign",
    enum: ["OWNER", "ADMIN", "READER"],
    example: "ADMIN",
  })
  @IsEnum(OrganizationRole)
  role: OrganizationRole;
}
