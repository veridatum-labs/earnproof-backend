import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import {
  computeWebhookCommitment,
  verifyWebhookCommitment,
  CommitmentInput,
} from '../common/crypto/canonical-commitment';

@Injectable()
export class WebhookCommitmentReceiptsService {
  constructor(private readonly prisma: PrismaService) {}

  async recordCommitment(input: CommitmentInput & { lineageId: string; attemptedAt: Date }) {
    const computed = computeWebhookCommitment({
      ...input,
      // Bind commitment to lineageId + eventId (not attempt number) so retries hash identically
      deliveryId: input.lineageId,
      attemptedAtIso: input.attemptedAt.toISOString(),
    });

    const existing = await this.prisma.webhookPayloadCommitmentReceipt.findUnique({
      where: {
        organizationId_webhookId_lineageId: {
          organizationId: input.organizationId,
          webhookId: input.webhookEndpointId,
          lineageId: input.lineageId,
        },
      },
    });

    if (existing) {
      return this.prisma.webhookPayloadCommitmentReceipt.update({
        where: { id: existing.id },
        data: {
          lastAttemptedAt: input.attemptedAt,
          attemptCount: { increment: 1 },
        },
      });
    }

    return this.prisma.webhookPayloadCommitmentReceipt.create({
      data: {
        organizationId: input.organizationId,
        webhookId: input.webhookEndpointId,
        eventId: input.eventId,
        lineageId: input.lineageId,
        eventType: input.eventType,
        commitmentVersion: computed.commitmentVersion,
        commitmentHash: `sha256:${computed.commitmentHash}`,
        payloadSha256: `sha256:${computed.canonicalMetadata.payloadSha256 ?? ''}`,
        payloadByteLength: computed.payloadByteLength,
        canonicalMetadata: computed.canonicalMetadata,
        firstAttemptedAt: input.attemptedAt,
        lastAttemptedAt: input.attemptedAt,
        attemptCount: 1,
      },
    });
  }

  async getForTenant(organizationId: string, receiptId: string) {
    const receipt = await this.prisma.webhookPayloadCommitmentReceipt.findFirst({
      where: { id: receiptId, organizationId },
    });
    if (!receipt) {
      throw new NotFoundException('Webhook commitment receipt not found');
    }
    return receipt;
  }

  verify(expectedPrefixedHash: string, candidate: CommitmentInput): boolean {
    const rawHex = expectedPrefixedHash.replace(/^sha256:/, '');
    return verifyWebhookCommitment(rawHex, candidate);
  }
}