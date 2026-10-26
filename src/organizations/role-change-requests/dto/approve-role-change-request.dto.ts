import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString, MaxLength } from "class-validator";

export class ApproveRoleChangeRequestDto {
  @ApiPropertyOptional({
    description: "Optional notes or approval comments.",
    example: "Approved after verifying manager sign-off.",
    maxLength: 512,
  })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  reason?: string;
}
