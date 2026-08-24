import { ApiProperty } from "@nestjs/swagger";

export class SyncIssuerStatusResponseDto {
  @ApiProperty({ description: "Issuer ID" })
  issuerId: string;

  @ApiProperty({
    description: "Whether the sync was attempted",
  })
  synced: boolean;

  @ApiProperty({
    description: "Reason if not synced (disabled, failed, etc.)",
    nullable: true,
  })
  reason?: string;

  @ApiProperty({
    description: "Transaction hash if successfully synced to contract",
    nullable: true,
  })
  transactionHash?: string;

  @ApiProperty({
    description: "Error message if sync failed",
    nullable: true,
  })
  error?: string;

  @ApiProperty({
    description: "Current database status after sync attempt",
  })
  currentStatus: string;
}
