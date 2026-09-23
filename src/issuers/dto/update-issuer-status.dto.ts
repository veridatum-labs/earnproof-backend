import { ApiProperty } from "@nestjs/swagger";
import { IsEnum, IsInt, Min } from "class-validator";
import { ResourceStatus } from "@prisma/client";

export class UpdateIssuerStatusDto {
  @ApiProperty({
    description:
      "Current revision of the issuer. Required for optimistic concurrency control. Include the revision from the last read response.",
    example: 1,
  })
  @IsInt()
  @Min(1)
  revision: number;

  @ApiProperty({
    description:
      "Target status. Valid transitions: PENDING→ACTIVE, ACTIVE→SUSPENDED, SUSPENDED→ACTIVE, ACTIVE→REVOKED",
    enum: ["ACTIVE", "PENDING", "SUSPENDED", "REVOKED", "DELETED"],
  })
  @IsEnum(ResourceStatus)
  status: ResourceStatus;
}
