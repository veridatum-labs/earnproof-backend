import {
  ArrayMinSize,
  ArrayUnique,
  IsArray,
  IsDateString,
  IsIn,
  IsInt,
  IsOptional,
  IsString,
  Max,
  Min,
} from "class-validator";

export const INTERVAL_UNITS = ["day", "week", "month"] as const;
export type IntervalUnit = (typeof INTERVAL_UNITS)[number];

export class CreateRecurringIncomeProofDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayUnique()
  @IsString({ each: true })
  selectedPaymentIds!: string[];

  /**
   * The unit of each interval: "day", "week", or "month".
   */
  @IsString()
  @IsIn(INTERVAL_UNITS)
  intervalUnit!: IntervalUnit;

  /**
   * How many intervals must be present inside the overall period.
   * Every interval must contain at least one qualifying income payment.
   */
  @IsInt()
  @Min(2)
  @Max(120)
  intervalCount!: number;

  @IsString()
  assetCode!: string;

  @IsOptional()
  @IsString()
  assetIssuer?: string;

  @IsDateString()
  periodStart!: string;

  @IsDateString()
  periodEnd!: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(365)
  expiresInDays?: number;
}
