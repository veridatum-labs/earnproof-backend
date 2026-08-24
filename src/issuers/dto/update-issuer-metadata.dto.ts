import { ApiProperty } from "@nestjs/swagger";
import { IsObject } from "class-validator";

export class UpdateIssuerMetadataDto {
  @ApiProperty({
    description:
      "Public metadata about the issuer. Redacted to allowlist when returned to public endpoints.",
    example: {
      name: "Acme Payment Services",
      description: "A trusted payment issuer",
      logoUrl: "https://example.com/logo.png",
      supportEmail: "support@acme.example.com",
    },
  })
  @IsObject()
  publicMetadata: Record<string, any>;
}
