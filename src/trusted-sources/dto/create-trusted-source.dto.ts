import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString, IsUUID } from "class-validator";

export class CreateTrustedSourceDto {
  @ApiProperty({
    description: "The normalized source address (e.g., Stellar account address)",
    example: "GBXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  })
  @IsString()
  sourceAddress: string;

  @ApiPropertyOptional({
    description: "Optional human-readable name for the trusted source",
    example: "My Employer Account",
  })
  @IsOptional()
  @IsString()
  displayName?: string;

  @ApiPropertyOptional({
    description: "The type of source (e.g., 'stellar', 'payment_processor')",
    example: "stellar",
  })
  @IsOptional()
  @IsString()
  sourceType?: string;

  @ApiPropertyOptional({
    description: "Optional issuer ID to link this trusted source to a known issuer",
    example: "issuer_123abc",
  })
  @IsOptional()
  @IsUUID()
  issuerId?: string;
}
