import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsString, IsObject, IsOptional } from "class-validator";

export class CreateIssuerDto {
  @ApiProperty({
    description: "Organization ID this issuer belongs to",
    example: "cuid123",
  })
  @IsString()
  organizationId: string;

  @ApiProperty({
    description: "Stellar public key address for this issuer",
    example: "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
  })
  @IsString()
  stellarAddress: string;

  @ApiPropertyOptional({
    description: "Public metadata about the issuer (name, description, etc.)",
    example: {
      name: "Acme Payment Services",
      description: "A trusted payment issuer",
      logoUrl: "https://example.com/logo.png",
    },
  })
  @IsOptional()
  @IsObject()
  publicMetadata?: Record<string, any>;
}
