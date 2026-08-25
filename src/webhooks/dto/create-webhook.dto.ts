import { ApiProperty } from "@nestjs/swagger";
import {
  ArrayMaxSize,
  ArrayMinSize,
  ArrayUnique,
  IsArray,
  IsIn,
  IsString,
  IsUrl,
  MinLength,
} from "class-validator";
import { WEBHOOK_EVENT_TYPES, WebhookEventType } from "../webhook-event.types";

export class CreateWebhookDto {
  @ApiProperty({
    description: "HTTPS URL that will receive webhook deliveries",
    example: "https://example.com/webhooks/earnproof",
  })
  @IsUrl(
    { protocols: ["https"], require_tld: true, require_protocol: true },
    { message: "url must be a valid HTTPS URL with a TLD" },
  )
  url!: string;

  @ApiProperty({
    description:
      "Organization ID that owns this webhook endpoint. " +
      "The authenticated user must be the creator of the organization.",
    example: "clxyz1234",
  })
  @IsString()
  @MinLength(1)
  organizationId!: string;

  @ApiProperty({
    description: "Allowlisted event types to subscribe to",
    enum: WEBHOOK_EVENT_TYPES,
    isArray: true,
    example: ["proof.created", "proof.verified"],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(WEBHOOK_EVENT_TYPES.length)
  @ArrayUnique()
  @IsIn(WEBHOOK_EVENT_TYPES, { each: true })
  events!: WebhookEventType[];
}
