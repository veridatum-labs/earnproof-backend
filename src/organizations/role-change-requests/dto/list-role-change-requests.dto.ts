import { ApiPropertyOptional } from "@nestjs/swagger";
import { RoleChangeRequestStatus } from "@prisma/client";
import { Type } from "class-transformer";
import { IsEnum, IsInt, IsOptional, IsString, Max, Min } from "class-validator";

export class ListRoleChangeRequestsDto {
  @ApiPropertyOptional({
    enum: ["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"],
    description: "Filter by request status.",
  })
  @IsOptional()
  @IsEnum(["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"])
  status?: RoleChangeRequestStatus;

  @ApiPropertyOptional({
    description: "Filter by target user ID.",
  })
  @IsOptional()
  @IsString()
  targetUserId?: string;

  @ApiPropertyOptional({
    minimum: 1,
    default: 1,
    description: "Page number.",
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number;

  @ApiPropertyOptional({
    minimum: 1,
    maximum: 100,
    default: 20,
    description: "Page size.",
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}
