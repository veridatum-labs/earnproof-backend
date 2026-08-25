import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsIn, IsOptional, IsString, MinLength } from "class-validator";
import { WEBHOOK_EVENT_TYPES } from "../webhook-event.types";

export class ListDeliveriesDto {
  @ApiPropertyOptional({
    description: "Filter by event type",
    enum: WEBHOOK_EVENT_TYPES,
  })
  @IsOptional()
  @IsIn(WEBHOOK_EVENT_TYPES)
  eventType?: string;

  @ApiPropertyOptional({
    description:
      "Return only deliveries at or after this cursor (delivery ID) — " +
      "use the last delivery ID from the previous page for pagination",
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  after?: string;
}
