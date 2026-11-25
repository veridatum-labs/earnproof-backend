import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { randomBytes } from 'crypto';
import { WebhookOwnershipTransferStatus, WebhookSecretState } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';

const TRANSFER_TTL_MS = 24 * 60 * 60 * 1000;

@Injectable()
export class WebhookOwnershipTransferService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditService: AuditService,
    private readonly encryptSecret: (raw: string) => string,
  ) {}

  async initiateTransfer(params: {
    webhookId: string;
    sourceOrganizationId: string;
    targetOrganizationId: string;
    actorId: string;
    expectedRevision: number;
  }) {
    if (params.sourceOrganizationId === params.targetOrganizationId) {
      throw new BadRequestException('Source and destination organizations must differ');
    }

    const transfer = await this.prisma.$transaction(async (tx) => {
      const webhook = await tx.webhook.findFirst({
        where: { id: params.webhookId, organizationId: params.sourceOrganizationId },
      });
      if (!webhook) throw new NotFoundException('Webhook not found');

      // Pause delivery + bump revision atomically (optimistic lock)
      const paused = await tx.webhook.updateMany({
        where: {
          id: webhook.id,
          organizationId: params.sourceOrganizationId,
          revision: params.expectedRevision,
        },
        data: {
          deliveryPaused: true,
          deliveryPauseReason: 'OWNERSHIP_TRANSFER',
          revision: { increment: 1 },
        },
      });
      if (paused.count !== 1) {
        throw new ConflictException('Concurrent modification detected on webhook');
      }

      // `openWebhookKey` unique index guarantees at most one open transfer per webhook
      return tx.webhookOwnershipTransfer.create({
        data: {
          webhookId: webhook.id,
          sourceOrganizationId: params.sourceOrganizationId,
          targetOrganizationId: params.targetOrganizationId,
          initiatedById: params.actorId,
          openWebhookKey: webhook.id,
          expectedRevision: params.expectedRevision,
          previousPausedState: webhook.deliveryPaused,
          previousStatus: webhook.status,
          expiresAt: new Date(Date.now() + TRANSFER_TTL_MS),
        },
      });
    });

    await this.auditService.record({
      actor: { type: 'USER', id: params.actorId },
      action: 'webhook.transfer.initiated',
      outcome: 'SUCCESS',
      meta: {
        organizationId: params.sourceOrganizationId,
        webhookId: params.webhookId,
        transferId: transfer.id,
        targetOrganizationId: params.targetOrganizationId,
      },
    });

    return transfer;
  }

  async acceptTransfer(params: {
    transferId: string;
    targetOrganizationId: string;
    actorId: string;
  }) {
    const newRawSecret = `whsec_${randomBytes(32).toString('hex')}`;
    const newEncryptedSecret = this.encryptSecret(newRawSecret);
    const newKeyId = `wk_${randomBytes(8).toString('hex')}`;

    const completed = await this.prisma.$transaction(async (tx) => {
      const transfer = await tx.webhookOwnershipTransfer.findUnique({
        where: { id: params.transferId },
      });
      if (!transfer || transfer.targetOrganizationId !== params.targetOrganizationId) {
        throw new ForbiddenException('Not authorized to accept this transfer');
      }
      if (transfer.status !== WebhookOwnershipTransferStatus.PENDING_ACCEPTANCE) {
        throw new ConflictException(`Transfer is not pending (${transfer.status})`);
      }
      if (transfer.expiresAt.getTime() <= Date.now()) {
        throw new ConflictException('Transfer has expired');
      }

      // Claim transfer atomically and release openWebhookKey
      const claim = await tx.webhookOwnershipTransfer.updateMany({
        where: {
          id: transfer.id,
          status: WebhookOwnershipTransferStatus.PENDING_ACCEPTANCE,
        },
        data: {
          status: WebhookOwnershipTransferStatus.COMPLETED,
          acceptedById: params.actorId,
          openWebhookKey: null,
          rotatedKeyId: newKeyId,
          completedAt: new Date(),
        },
      });
      if (claim.count !== 1) {
        throw new ConflictException('Concurrent transfer state transition detected');
      }

      const webhook = await tx.webhook.findFirst({
        where: { id: transfer.webhookId, organizationId: transfer.sourceOrganizationId },
      });
      if (!webhook) throw new ConflictException('Webhook ownership changed concurrently');

      // 1. Retire ALL existing ACTIVE & OVERLAP secret versions so no old key crosses boundary
      await tx.webhookSecretVersion.updateMany({
        where: {
          webhookId: webhook.id,
          state: { in: [WebhookSecretState.ACTIVE, WebhookSecretState.OVERLAP] },
        },
        data: { state: WebhookSecretState.RETIRED, overlapExpiresAt: new Date() },
      });

      // 2. Create fresh ACTIVE secret version for destination organization
      await tx.webhookSecretVersion.create({
        data: {
          webhookId: webhook.id,
          keyId: newKeyId,
          secretEncrypted: newEncryptedSecret,
          state: WebhookSecretState.ACTIVE,
        },
      });

      // 3. Move webhook ownership & rotate primary secret with optimistic revision check
      const moved = await tx.webhook.updateMany({
        where: {
          id: webhook.id,
          organizationId: transfer.sourceOrganizationId,
          revision: webhook.revision,
        },
        data: {
          organizationId: params.targetOrganizationId,
          secretEncrypted: newEncryptedSecret,
          deliveryPaused: false,
          deliveryPauseReason: null,
          revision: { increment: 1 },
        },
      });
      if (moved.count !== 1) {
        throw new ConflictException('Concurrent webhook update blocked transfer completion');
      }

      return transfer;
    });

    await this.auditService.record({
      actor: { type: 'USER', id: params.actorId },
      action: 'webhook.transfer.completed',
      outcome: 'SUCCESS',
      meta: {
        transferId: completed.id,
        webhookId: completed.webhookId,
        sourceOrganizationId: completed.sourceOrganizationId,
        targetOrganizationId: completed.targetOrganizationId,
        rotatedKeyId: newKeyId,
      },
    });

    return {
      transferId: completed.id,
      webhookId: completed.webhookId,
      keyId: newKeyId,
      signingSecret: newRawSecret, // Returned once to destination admin
    };
  }

  async cancelOrRollbackTransfer(params: {
    transferId: string;
    actorOrganizationId: string;
    actorId: string;
    rollback?: boolean;
  }) {
    const nextStatus = params.rollback
      ? WebhookOwnershipTransferStatus.ROLLED_BACK
      : WebhookOwnershipTransferStatus.CANCELLED;

    const result = await this.prisma.$transaction(async (tx) => {
      const transfer = await tx.webhookOwnershipTransfer.findUnique({
        where: { id: params.transferId },
      });
      if (
        !transfer ||
        (transfer.sourceOrganizationId !== params.actorOrganizationId &&
          transfer.targetOrganizationId !== params.actorOrganizationId)
      ) {
        throw new ForbiddenException('Not authorized to cancel this transfer');
      }

      const claim = await tx.webhookOwnershipTransfer.updateMany({
        where: { id: transfer.id, status: WebhookOwnershipTransferStatus.PENDING_ACCEPTANCE },
        data: {
          status: nextStatus,
          cancelledById: params.actorId,
          cancelledAt: new Date(),
          openWebhookKey: null,
        },
      });
      if (claim.count !== 1) {
        throw new ConflictException('Transfer cannot be cancelled in its current state');
      }

      await tx.webhook.updateMany({
        where: { id: transfer.webhookId, organizationId: transfer.sourceOrganizationId },
        data: {
          deliveryPaused: transfer.previousPausedState,
          deliveryPauseReason: null,
          revision: { increment: 1 },
        },
      });

      return transfer;
    });

    await this.auditService.record({
      actor: { type: 'USER', id: params.actorId },
      action: params.rollback ? 'webhook.transfer.rolled_back' : 'webhook.transfer.cancelled',
      outcome: 'SUCCESS',
      meta: {
        transferId: result.id,
        webhookId: result.webhookId,
        organizationId: result.sourceOrganizationId,
      },
    });

    return { transferId: result.id, status: nextStatus };
  }
}