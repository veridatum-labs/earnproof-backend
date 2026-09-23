import { ApiProperty } from "@nestjs/swagger";
import { IsEnum } from "class-validator";
import { OrganizationRole } from "@prisma/client";

export class UpdateMemberRoleDto {
  @ApiProperty({
    description: "New role for the member",
    enum: ["OWNER", "ADMIN", "READER"],
    example: "READER",
  })
  @IsEnum(OrganizationRole)
  role: OrganizationRole;
}
