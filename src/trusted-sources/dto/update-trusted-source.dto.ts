import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsNotEmpty, IsOptional, IsString, MaxLength, IsInt, Min } from "class-validator";

export class UpdateTrustedSourceDto {
  @ApiProperty({
    description:
      "Current revision of the trusted source. Required for optimistic concurrency control. Include the revision from the last read response.",
    example: 1,
  })
  @IsInt()
  @Min(1)
  revision: number;

  @ApiPropertyOptional({
    description: "Updated human-readable name for the trusted source",
    example: "My Employer Account - Updated",
  })
  @IsOptional()
  @IsString()
  @MaxLength(120)
  displayName?: string;

  @ApiPropertyOptional({
    description: "Updated issuer ID to link this trusted source to a known issuer",
    example: "issuer_456def",
  })
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  issuerId?: string;
}
