import { ApiProperty } from "@nestjs/swagger";
import { IsArray, IsIn, ArrayMinSize, ArrayMaxSize, IsInt, Min } from "class-validator";
import { WEBHOOK_EVENT_TYPES, WebhookEventType } from "../webhook-event.types";

export class UpdateWebhookEventsDto {
  @ApiProperty({
    description:
      "Current revision of the webhook. Required for optimistic concurrency control. Include the revision from the last read response.",
    example: 1,
  })
  @IsInt()
  @Min(1)
  revision: number;

  @ApiProperty({
    description: "Replacement set of event type subscriptions",
    type: [String],
    enum: WEBHOOK_EVENT_TYPES,
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(WEBHOOK_EVENT_TYPES.length)
  @IsIn(WEBHOOK_EVENT_TYPES as unknown as string[], { each: true })
  events!: WebhookEventType[];
}
