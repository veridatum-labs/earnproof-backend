import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { AuthenticatedUser } from "../auth/auth.types";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { PrismaService } from "../database/prisma.service";
import { CreateWebhookDto } from "./dto/create-webhook.dto";
import { UpdateWebhookEventsDto } from "./dto/update-webhook-events.dto";
import { WebhooksService } from "./webhooks.service";

/**
 * Resolves the organisation ID from the current authenticated user.
 *
 * The JWT carries userId only.  We query the first ACTIVE organisation
 * the user belongs to.  In a multi-org scenario the org could be passed
 * as a path or query param — kept simple here per scope constraints.
 */
@ApiTags("webhooks")
@ApiBearerAuth()
@UseGuards(AuthGuard)
@Controller("webhooks")
export class WebhooksController {
  constructor(
    private readonly webhooksService: WebhooksService,
    private readonly prisma: PrismaService,
  ) {}

  // ---------------------------------------------------------------------------
  // Endpoint management
  // ---------------------------------------------------------------------------

  @Post()
  @ApiOperation({ summary: "Create a webhook endpoint" })
  async create(@CurrentUser() user: AuthenticatedUser, @Body() dto: CreateWebhookDto) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.create(orgId, dto);
  }

  @Get()
  @ApiOperation({ summary: "List webhook endpoints for your organisation" })
  async list(@CurrentUser() user: AuthenticatedUser) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.listForOrg(orgId);
  }

  @Get(":id")
  @ApiOperation({ summary: "Get a webhook endpoint" })
  async get(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.getForOrg(orgId, id);
  }

  @Patch(":id/events")
  @ApiOperation({ summary: "Update event subscriptions" })
  async updateEvents(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
    @Body() dto: UpdateWebhookEventsDto,
  ) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.updateEvents(orgId, id, dto);
  }

  @Post(":id/rotate-secret")
  @ApiOperation({ summary: "Rotate the signing secret (returns new secret once)" })
  async rotateSecret(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.rotateSecret(orgId, id);
  }

  @Patch(":id/disable")
  @ApiOperation({ summary: "Disable a webhook endpoint" })
  async disable(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.disable(orgId, id);
  }

  @Patch(":id/enable")
  @ApiOperation({ summary: "Re-enable a webhook endpoint" })
  async enable(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.enable(orgId, id);
  }

  @Delete(":id")
  @ApiOperation({ summary: "Delete a webhook endpoint" })
  async delete(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.delete(orgId, id);
  }

  // ---------------------------------------------------------------------------
  // Delivery observability
  // ---------------------------------------------------------------------------

  @Get(":id/deliveries")
  @ApiOperation({ summary: "List delivery records for a webhook endpoint" })
  async listDeliveries(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.listDeliveries(orgId, id);
  }

  // ---------------------------------------------------------------------------
  // Manual replay
  // ---------------------------------------------------------------------------

  @Post("deliveries/:deliveryId/replay")
  @ApiOperation({ summary: "Manually replay a delivery (DEVELOPER or ADMIN only)" })
  async replayDelivery(
    @CurrentUser() user: AuthenticatedUser,
    @Param("deliveryId") deliveryId: string,
  ) {
    this.requirePrivilegedRole(user);
    const orgId = await this.requireOrgId(user);
    return this.webhooksService.replayDelivery(orgId, deliveryId, user.id);
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private async requireOrgId(user: AuthenticatedUser): Promise<string> {
    // Find an active organization the user belongs to
    const userWithOrgs = await this.prisma.user.findUnique({
      where: { id: user.id },
      select: {
        organizations: {
          where: { status: "ACTIVE" },
          select: { id: true },
          take: 1,
        },
      },
    });

    if (!userWithOrgs?.organizations?.[0]) {
      throw new ForbiddenException("No active organisation found for this user");
    }

    return userWithOrgs.organizations[0].id;
  }

  private requirePrivilegedRole(user: AuthenticatedUser): void {
    if (user.role !== "DEVELOPER" && user.role !== "ADMIN") {
      throw new ForbiddenException(
        "Only DEVELOPER or ADMIN users may replay webhook deliveries",
      );
    }
  }
}
