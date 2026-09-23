import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsString, IsUrl, IsOptional, MinLength, IsInt, Min } from "class-validator";

export class UpdateOrganizationDto {
  @ApiProperty({
    description:
      "Current revision of the organization. Required for optimistic concurrency control. Include the revision from the last read response.",
    example: 1,
  })
  @IsInt()
  @Min(1)
  revision: number;

  @ApiPropertyOptional({
    description: "Organization display name",
    example: "Acme Corporation",
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  name?: string;

  @ApiPropertyOptional({
    description: "Organization website URL",
    example: "https://acme.example.com",
  })
  @IsOptional()
  @IsUrl()
  website?: string;
}
