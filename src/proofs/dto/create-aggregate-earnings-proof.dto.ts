import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsDateString,
  IsInt,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from "class-validator";
import { FIELD_LIMITS } from "../../common/limits/request-limits";

export class CreateAggregateEarningsProofDto {
  @ApiProperty({
    description:
      "IDs of the payments to aggregate. Every payment must belong to the authenticated " +
      "user, be classified INCOME, be eligible, use the requested asset, and fall inside " +
      "the requested period. Duplicate payments are counted once.",
    type: [String],
    example: ["clx1abc2def3ghi4", "clx1xyz5uvw6rst7"],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(FIELD_LIMITS.paymentIdsPerProof)
  @IsString({ each: true })
  @MaxLength(FIELD_LIMITS.id, { each: true })
  selectedPaymentIds!: string[];

  @ApiProperty({
    description:
      "Stellar asset code that all selected payments must share. Mixed-asset selections " +
      "are rejected unless an explicit conversion policy is configured.",
    example: "USDC",
  })
  @IsString()
  @MaxLength(FIELD_LIMITS.assetCode)
  assetCode!: string;

  @ApiPropertyOptional({
    description:
      "Stellar issuer address for the asset. Omit for native XLM. All selected payments " +
      "must share this issuer.",
    example: "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGLA1PIC4CEXLRTKHB0EGB",
  })
  @IsOptional()
  @IsString()
  @MaxLength(FIELD_LIMITS.stellarAddress)
  assetIssuer?: string;

  @ApiProperty({
    description:
      "ISO-8601 date string for the start of the aggregation period (inclusive).",
    example: "2025-01-01T00:00:00.000Z",
  })
  @IsDateString()
  periodStart!: string;

  @ApiProperty({
    description:
      "ISO-8601 date string for the end of the aggregation period (inclusive). Must be on " +
      "or after periodStart and at most 366 days after it.",
    example: "2025-12-31T23:59:59.000Z",
  })
  @IsDateString()
  periodEnd!: string;

  @ApiPropertyOptional({
    description:
      "Named conversion policy used to combine payments of different assets. No conversion " +
      "policy is currently supported, so supplying one is rejected; omit it to aggregate a " +
      "single asset.",
    example: "oracle-spot/v1",
  })
  @IsOptional()
  @IsString()
  @MaxLength(FIELD_LIMITS.name)
  conversionPolicy?: string;

  @ApiPropertyOptional({
    description:
      "Number of days until the proof expires. Defaults to 30. Must be between 1 and 365.",
    minimum: 1,
    maximum: 365,
    example: 30,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(365)
  expiresInDays?: number;
}
