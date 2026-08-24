import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsString, IsUrl, IsOptional, Matches, MinLength } from "class-validator";

export class CreateOrganizationDto {
  @ApiProperty({
    description: "Organization display name",
    example: "Acme Corporation",
  })
  @IsString()
  @MinLength(1)
  name: string;

  @ApiProperty({
    description: "Organization URL slug (lowercase, alphanumeric, hyphens)",
    example: "acme-corp",
  })
  @IsString()
  @Matches(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, {
    message: "slug must be lowercase alphanumeric with hyphens only",
  })
  slug: string;

  @ApiPropertyOptional({
    description: "Organization website URL",
    example: "https://acme.example.com",
  })
  @IsOptional()
  @IsUrl()
  website?: string;
}
