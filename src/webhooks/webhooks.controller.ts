import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { AuthenticatedUser } from "../auth/auth.types";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { CreateWebhookDto } from "./dto/create-webhook.dto";
import { ListDeliveriesDto } from "./dto/list-deliveries.dto";
import { WebhookDeliveryService } from "./webhook-delivery.service";
import { WebhooksService } from "./webhooks.service";

@ApiBearerAuth()
@ApiTags("webhooks")
@UseGuards(AuthGuard)
@Controller("webhooks")
export class WebhooksController {
  constructor(
    private readonly webhooksService: WebhooksService,
    private readonly deliveryService: WebhookDeliveryService,
  ) {}

  // ---------------------------------------------------------------------------
  // Endpoint management
  // ---------------------------------------------------------------------------

  @ApiOperation({
    summary: "Register a new webhook endpoint",
    description:
      "The signing secret is returned ONLY in this response. " +
      "Store it securely — it cannot be retrieved again (only rotated).",
  })
  @Post()
  createWebhook(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateWebhookDto,
  ) {
    return this.webhooksService.createWebhook(user.id, body);
  }

  @ApiOperation({ summary: "List webhook endpoints for an organization" })
  @Get()
  listWebhooks(
    @CurrentUser() user: AuthenticatedUser,
    @Query("organizationId") organizationId: string,
  ) {
    return this.webhooksService.listWebhooks(user.id, organizationId);
  }

  @ApiOperation({ summary: "Get a single webhook endpoint" })
  @Get(":id")
  getWebhook(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.webhooksService.getWebhook(user.id, id);
  }

  @ApiOperation({
    summary: "Rotate the signing secret for a webhook endpoint",
    description:
      "Invalidates the old secret immediately. " +
      "The new secret is returned ONLY in this response.",
  })
  @Post(":id/rotate-secret")
  @HttpCode(HttpStatus.OK)
  rotateSecret(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.webhooksService.rotateSecret(user.id, id);
  }

  @ApiOperation({ summary: "Disable a webhook endpoint (suspend deliveries)" })
  @Patch(":id/disable")
  disableWebhook(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.webhooksService.disableWebhook(user.id, id);
  }

  @ApiOperation({ summary: "Re-enable a previously disabled webhook endpoint" })
  @Patch(":id/enable")
  enableWebhook(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.webhooksService.enableWebhook(user.id, id);
  }

  @ApiOperation({
    summary: "Delete a webhook endpoint",
    description: "Soft-deletes the endpoint. Delivery history is preserved.",
  })
  @Delete(":id")
  deleteWebhook(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.webhooksService.deleteWebhook(user.id, id);
  }

  // ---------------------------------------------------------------------------
  // Delivery logs
  // ---------------------------------------------------------------------------

  @ApiOperation({
    summary: "List delivery records for a webhook endpoint",
    description: "Results are paginated (50 per page, ordered oldest-first).",
  })
  @Get(":id/deliveries")
  listDeliveries(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") webhookId: string,
    @Query() query: ListDeliveriesDto,
    @Query("organizationId") organizationId: string,
  ) {
    return this.deliveryService.listDeliveries(webhookId, organizationId, {
      eventType: query.eventType,
      after: query.after,
    });
  }

  // ---------------------------------------------------------------------------
  // Manual replay
  // ---------------------------------------------------------------------------

  @ApiOperation({
    summary: "Manually replay a delivery",
    description:
      "Re-sends the delivery using the same deliveryId so integrators " +
      "can deduplicate. Caller must own the webhook's organization. " +
      "The replay is audited (actor and timestamp recorded).",
  })
  @Post(":id/deliveries/:deliveryDbId/replay")
  @HttpCode(HttpStatus.OK)
  replayDelivery(
    @CurrentUser() user: AuthenticatedUser,
    @Param("deliveryDbId") deliveryDbId: string,
  ) {
    return this.deliveryService.replayDelivery(deliveryDbId, user.id);
  }
}
