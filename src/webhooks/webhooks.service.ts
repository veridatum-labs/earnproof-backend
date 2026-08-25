/**
 * WebhooksService
 *
 * Manages webhook endpoint lifecycle:
 *   - Create (generates signing secret, stores encrypted + hashed)
 *   - List (no secrets returned)
 *   - Get (no secrets returned)
 *   - Rotate secret (old secret invalidated immediately)
 *   - Disable / re-enable
 *   - Delete (soft-delete via ResourceStatus.DELETED)
 *
 * Authorization: all mutations require the caller to be the `createdBy` user
 * of the Organization that owns the webhook.  A full membership table is out
 * of scope for this change (see trade-offs in PR description).
 *
 * Secret handling:
 *   - Raw secret is generated once and returned ONLY at creation / rotation.
 *   - It is stored as `secretEncrypted` (AES-256-GCM) so the delivery service
 *     can recover it at send time.
 *   - `secretHash` (SHA-256 hex) is stored for fast duplicate detection only.
 *   - Neither field is returned by any list/get response.
 */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ResourceStatus } from "@prisma/client";
import { encryptProtectedAmount } from "../common/crypto/protected-amount";
import { sha256 } from "../common/crypto/hash";
import { PrismaService } from "../database/prisma.service";
import { SsrfGuard } from "./ssrf.guard";
import {
  isWebhookEventType,
  WEBHOOK_EVENT_TYPES,
} from "./webhook-event.types";
import { WebhookSigningService } from "./webhook-signing.service";
import { CreateWebhookDto } from "./dto/create-webhook.dto";

@Injectable()
export class WebhooksService {
  private readonly webhookEncryptionKey: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly signing: WebhookSigningService,
    configService: ConfigService,
  ) {
    this.webhookEncryptionKey =
      configService.getOrThrow<string>("webhookEncryptionKey");
  }

  // ---------------------------------------------------------------------------
  // Endpoint management
  // ---------------------------------------------------------------------------

  async createWebhook(userId: string, dto: CreateWebhookDto) {
    await this.assertOrgOwnership(userId, dto.organizationId);
    this.validateEvents(dto.events);

    // SSRF check at registration time
    await SsrfGuard.assertSafeUrl(dto.url);

    const rawSecret = this.signing.generateSecret();
    const secretEncrypted = encryptProtectedAmount(
      rawSecret,
      this.webhookEncryptionKey,
    );
    const secretHash = sha256(rawSecret);

    const webhook = await this.prisma.webhook.create({
      data: {
        organizationId: dto.organizationId,
        url: dto.url,
        secretHash,
        secretEncrypted,
        events: dto.events,
        status: ResourceStatus.ACTIVE,
      },
      select: {
        id: true,
        organizationId: true,
        url: true,
        events: true,
        status: true,
        createdAt: true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: userId,
        action: "webhook.created",
        resourceType: "webhook",
        resourceId: webhook.id,
        metadata: { url: dto.url, events: dto.events },
      },
    });

    // Raw secret returned ONLY here — never again
    return { ...webhook, secret: rawSecret };
  }

  async listWebhooks(userId: string, organizationId: string) {
    await this.assertOrgOwnership(userId, organizationId);

    return this.prisma.webhook.findMany({
      where: {
        organizationId,
        status: { not: ResourceStatus.DELETED },
      },
      select: {
        id: true,
        organizationId: true,
        url: true,
        events: true,
        status: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async getWebhook(userId: string, webhookId: string) {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        status: { not: ResourceStatus.DELETED },
      },
      select: {
        id: true,
        organizationId: true,
        url: true,
        events: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        organization: { select: { createdById: true } },
      },
    });

    if (!webhook) throw new NotFoundException("Webhook not found");
    if (webhook.organization.createdById !== userId) {
      throw new NotFoundException("Webhook not found");
    }

    const { organization: _org, ...safe } = webhook;
    return safe;
  }

  /**
   * Rotate the signing secret for an endpoint.
   *
   * The old secret is invalidated immediately. Any in-flight deliveries that
   * were signed with the old secret and are awaiting acknowledgement will
   * fail verification on the integrator side. Integrators should:
   *   1. Update their stored secret after calling this endpoint.
   *   2. Replay any unacknowledged deliveries via POST /webhooks/:id/deliveries/:dId/replay.
   *
   * The new raw secret is returned ONLY in this response.
   */
  async rotateSecret(userId: string, webhookId: string) {
    const webhook = await this.findOwnedWebhook(userId, webhookId);

    const rawSecret = this.signing.generateSecret();
    const secretEncrypted = encryptProtectedAmount(
      rawSecret,
      this.webhookEncryptionKey,
    );
    const secretHash = sha256(rawSecret);

    await this.prisma.webhook.update({
      where: { id: webhook.id },
      data: { secretHash, secretEncrypted },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: userId,
        action: "webhook.secret.rotated",
        resourceType: "webhook",
        resourceId: webhook.id,
        metadata: { url: webhook.url },
      },
    });

    return { id: webhook.id, secret: rawSecret };
  }

  async disableWebhook(userId: string, webhookId: string) {
    const webhook = await this.findOwnedWebhook(userId, webhookId);

    await this.prisma.webhook.update({
      where: { id: webhook.id },
      data: { status: ResourceStatus.SUSPENDED },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: userId,
        action: "webhook.disabled",
        resourceType: "webhook",
        resourceId: webhook.id,
        metadata: {},
      },
    });

    return { id: webhook.id, status: ResourceStatus.SUSPENDED };
  }

  async enableWebhook(userId: string, webhookId: string) {
    const webhook = await this.findOwnedWebhook(userId, webhookId);

    await this.prisma.webhook.update({
      where: { id: webhook.id },
      data: { status: ResourceStatus.ACTIVE },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: userId,
        action: "webhook.enabled",
        resourceType: "webhook",
        resourceId: webhook.id,
        metadata: {},
      },
    });

    return { id: webhook.id, status: ResourceStatus.ACTIVE };
  }

  async deleteWebhook(userId: string, webhookId: string) {
    const webhook = await this.findOwnedWebhook(userId, webhookId);

    await this.prisma.webhook.update({
      where: { id: webhook.id },
      data: { status: ResourceStatus.DELETED },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: userId,
        action: "webhook.deleted",
        resourceType: "webhook",
        resourceId: webhook.id,
        metadata: {},
      },
    });

    return { id: webhook.id, deleted: true };
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private async assertOrgOwnership(userId: string, organizationId: string) {
    const org = await this.prisma.organization.findFirst({
      where: { id: organizationId },
      select: { createdById: true },
    });

    if (!org) throw new NotFoundException("Organization not found");
    if (org.createdById !== userId) {
      throw new ForbiddenException(
        "You do not have permission to manage webhooks for this organization",
      );
    }
  }

  private async findOwnedWebhook(userId: string, webhookId: string) {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        status: { not: ResourceStatus.DELETED },
      },
      select: {
        id: true,
        url: true,
        organization: { select: { createdById: true } },
      },
    });

    if (!webhook) throw new NotFoundException("Webhook not found");
    if (webhook.organization.createdById !== userId) {
      throw new NotFoundException("Webhook not found");
    }

    return webhook;
  }

  private validateEvents(events: unknown[]) {
    const invalid = events.filter((e) => !isWebhookEventType(e));
    if (invalid.length > 0) {
      throw new BadRequestException(
        `Invalid event type(s): ${invalid.join(", ")}. ` +
          `Allowed: ${WEBHOOK_EVENT_TYPES.join(", ")}`,
      );
    }
  }
}
