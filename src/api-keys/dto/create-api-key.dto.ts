import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsDateString,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from "class-validator";
import { API_KEY_SCOPES, ApiKeyScope } from "../api-key-scopes";

export class CreateApiKeyDto {
  @ApiProperty({ example: "CI pipeline key" })
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  name!: string;

  @ApiProperty({
    description: "Least-privilege scopes granted to this key",
    enum: API_KEY_SCOPES,
    isArray: true,
    example: ["proofs:read"],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(API_KEY_SCOPES.length)
  @IsIn(API_KEY_SCOPES, { each: true })
  scopes!: ApiKeyScope[];

  @ApiPropertyOptional({
    description: "ISO-8601 expiry date-time; omit for no expiry",
    example: "2027-01-01T00:00:00Z",
  })
  @IsOptional()
  @IsDateString()
  expiresAt?: string;
}
