import {
  Injectable,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { randomBytes } from 'crypto';
import { PrismaService } from '../database/prisma.service';
import { WebhookTransferStatus } from '@prisma/client';

const TRANSFER_TTL_MS = 24 * 60 * 60 * 1000;

@Injectable()
export class WebhookTransferService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly secretEncryptor: { encrypt(raw: string): string },
    private readonly auditLogger: { record(entry: Record<string, unknown>): Promise<void> },
  ) {}

  async initiateTransfer(params: {
    endpointId: string;
    sourceOrgId: string;
    targetOrgId: string;
    actorUserId: string;
    expectedVersion: number;
  }) {
    if (params.sourceOrgId === params.targetOrgId) {
      throw new BadRequestException('Source and destination organizations must differ');
    }

    const result = await this.prisma.$transaction(async (tx) => {
      const endpoint = await tx.webhookEndpoint.findFirst({
        where: { id: params.endpointId, organizationId: params.sourceOrgId },
      });
      if (!endpoint) throw new NotFoundException('Webhook endpoint not found');

      const existing = await tx.webhookOwnershipTransfer.findFirst({
        where: { webhookEndpointId: endpoint.id, status: WebhookTransferStatus.PENDING_ACCEPTANCE },
      });
      if (existing) throw new ConflictException('A transfer is already pending for this endpoint');

      // Optimistic lock prevents concurrent update/transfer race
      const updated = await tx.webhookEndpoint.updateMany({
        where: { id: endpoint.id, organizationId: params.sourceOrgId, version: params.expectedVersion },
        data: {
          deliveryPaused: true,
          deliveryPauseReason: 'OWNERSHIP_TRANSFER',
          version: { increment: 1 },
        },
      });
      if (updated.count !== 1) {
        throw new ConflictException('Concurrent modification detected on webhook endpoint');
      }

      return tx.webhookOwnershipTransfer.create({
        data: {
          webhookEndpointId: endpoint.id,
          sourceOrganizationId: params.sourceOrgId,
          targetOrganizationId: params.targetOrgId,
          initiatedByUserId: params.actorUserId,
          previousPausedState: endpoint.deliveryPaused,
          expiresAt: new Date(Date.now() + TRANSFER_TTL_MS),
        },
      });
    });

    await this.auditLogger.record({
      category: 'WEBHOOK_TRANSFER',
      action: 'webhook.transfer.initiated',
      organizationId: params.sourceOrgId,
      actorId: params.actorUserId,
      resourceId: params.endpointId,
      safeMetadata: { transferId: result.id, targetOrgId: params.targetOrgId },
    });

    return result;
  }

  async acceptTransfer(params: {
    transferId: string;
    targetOrgId: string;
    actorUserId: string;
  }) {
    const newRawSecret = `whsec_${randomBytes(32).toString('hex')}`;
    const newEncryptedSecret = this.secretEncryptor.encrypt(newRawSecret);

    const completed = await this.prisma.$transaction(async (tx) => {
      const transfer = await tx.webhookOwnershipTransfer.findUnique({
        where: { id: params.transferId },
      });
      if (!transfer || transfer.targetOrganizationId !== params.targetOrgId) {
        throw new ForbiddenException('Not authorized to accept this transfer');
      }
      if (transfer.status !== WebhookTransferStatus.PENDING_ACCEPTANCE) {
        throw new ConflictException(`Transfer is no longer pending (status: ${transfer.status})`);
      }
      if (transfer.expiresAt.getTime() <= Date.now()) {
        throw new ConflictException('Transfer has expired');
      }

      // Claim transfer atomically
      const claim = await tx.webhookOwnershipTransfer.updateMany({
        where: { id: transfer.id, status: WebhookTransferStatus.PENDING_ACCEPTANCE },
        data: {
          status: WebhookTransferStatus.COMPLETED,
          acceptedByUserId: params.actorUserId,
          completedAt: new Date(),
        },
      });
      if (claim.count !== 1) {
        throw new ConflictException('Concurrent transfer state change detected');
      }

      const endpoint = await tx.webhookEndpoint.findFirst({
        where: { id: transfer.webhookEndpointId, organizationId: transfer.sourceOrganizationId },
      });
      if (!endpoint) throw new ConflictException('Endpoint ownership changed concurrently');

      // Rotate secret so source org's secret NEVER crosses the org boundary
      const moved = await tx.webhookEndpoint.updateMany({
        where: { id: endpoint.id, organizationId: transfer.sourceOrganizationId, version: endpoint.version },
        data: {
          organizationId: params.targetOrgId,
          signingSecretEncrypted: newEncryptedSecret,
          deliveryPaused: false,
          deliveryPauseReason: null,
          version: { increment: 1 },
        },
      });
      if (moved.count !== 1) {
        throw new ConflictException('Concurrent endpoint update blocked transfer completion');
      }

      return transfer;
    });

    await Promise.all([
      this.auditLogger.record({
        category: 'WEBHOOK_TRANSFER',
        action: 'webhook.transfer.completed',
        organizationId: completed.sourceOrganizationId,
        actorId: params.actorUserId,
        resourceId: completed.webhookEndpointId,
        safeMetadata: { transferId: completed.id, direction: 'outbound' },
      }),
      this.auditLogger.record({
        category: 'WEBHOOK_TRANSFER',
        action: 'webhook.transfer.completed',
        organizationId: completed.targetOrganizationId,
        actorId: params.actorUserId,
        resourceId: completed.webhookEndpointId,
        safeMetadata: { transferId: completed.id, direction: 'inbound', secretRotated: true },
      }),
    ]);

    // Return new secret once to destination admin
    return { transferId: completed.id, endpointId: completed.webhookEndpointId, signingSecret: newRawSecret };
  }

  async rollbackOrCancelTransfer(params: {
    transferId: string;
    actorOrgId: string;
    actorUserId: string;
    isRollback?: boolean;
  }) {
    const nextStatus = params.isRollback ? WebhookTransferStatus.ROLLED_BACK : WebhookTransferStatus.CANCELLED;

    const cancelled = await this.prisma.$transaction(async (tx) => {
      const transfer = await tx.webhookOwnershipTransfer.findUnique({ where: { id: params.transferId } });
      if (
        !transfer ||
        (transfer.sourceOrganizationId !== params.actorOrgId && transfer.targetOrganizationId !== params.actorOrgId)
      ) {
        throw new ForbiddenException('Not authorized to cancel this transfer');
      }

      const claim = await tx.webhookOwnershipTransfer.updateMany({
        where: { id: transfer.id, status: WebhookTransferStatus.PENDING_ACCEPTANCE },
        data: { status: nextStatus, cancelledByUserId: params.actorUserId },
      });
      if (claim.count !== 1) {
        throw new ConflictException('Transfer cannot be cancelled in its current state');
      }

      await tx.webhookEndpoint.updateMany({
        where: { id: transfer.webhookEndpointId, organizationId: transfer.sourceOrganizationId },
        data: {
          deliveryPaused: transfer.previousPausedState,
          deliveryPauseReason: null,
          version: { increment: 1 },
        },
      });

      return transfer;
    });

    await this.auditLogger.record({
      category: 'WEBHOOK_TRANSFER',
      action: params.isRollback ? 'webhook.transfer.rolled_back' : 'webhook.transfer.cancelled',
      organizationId: cancelled.sourceOrganizationId,
      actorId: params.actorUserId,
      resourceId: cancelled.webhookEndpointId,
      safeMetadata: { transferId: cancelled.id },
    });

    return { transferId: cancelled.id, status: nextStatus };
  }
}