import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString } from "class-validator";

export class ListApiKeysDto {
  @ApiPropertyOptional({ description: "Filter by organization ID" })
  @IsOptional()
  @IsString()
  organizationId?: string;
}
