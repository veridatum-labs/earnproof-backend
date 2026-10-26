import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString, MaxLength } from "class-validator";

export class CancelRoleChangeRequestDto {
  @ApiPropertyOptional({
    description: "Optional cancellation reason.",
    example: "No longer needed.",
    maxLength: 512,
  })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  reason?: string;
}
