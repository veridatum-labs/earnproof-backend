import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { AuditLog, Prisma } from '@prisma/client';
import { PrismaService } from '../database/prisma.service';
import {
  AuditFieldPolicyContext,
  projectAuditLogRecord,
} from '../common/audit/audit-field-policy';

export interface AuditRecordOptions {
  actor: { type: string; id: string };
  action: string;
  outcome: string;
  meta?: Record<string, unknown>;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  async record(options: AuditRecordOptions): Promise<void> {
    try {
      this.logger.log(
        `Audit: actor=${options.actor.type}:${options.actor.id} action=${options.action} outcome=${options.outcome}`,
      );
    } catch (error) {
      this.logger.warn(
        `Failed to record audit event: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async listForContext(
    ctx: Omit<AuditFieldPolicyContext, 'purpose'>,
    filter: { action?: string; resourceType?: string; take?: number } = {},
  ) {
    const where: Prisma.AuditLogWhereInput = {
      ...(ctx.role !== 'PLATFORM_OPERATOR' ? { organizationId: ctx.organizationId ?? '__NONE__' } : {}),
      ...(filter.action ? { action: filter.action } : {}),
      ...(filter.resourceType ? { resourceType: filter.resourceType } : {}),
    };

    const rows = await this.prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: Math.min(filter.take ?? 50, 200),
    });

    return this.applyFieldPolicy(rows, { ...ctx, purpose: 'LIST' });
  }

  async getDetailForContext(
    id: string,
    ctx: Omit<AuditFieldPolicyContext, 'purpose'> & { purpose?: 'DETAIL' | 'SECURITY_INVESTIGATION' },
  ) {
    const row = await this.prisma.auditLog.findFirst({
      where: {
        id,
        ...(ctx.role !== 'PLATFORM_OPERATOR' ? { organizationId: ctx.organizationId ?? '__NONE__' } : {}),
      },
    });
    if (!row) {
      throw new NotFoundException('Audit log record not found');
    }

    const [projected] = await this.applyFieldPolicy([row], {
      ...ctx,
      purpose: ctx.purpose ?? 'DETAIL',
    });
    if (!projected) {
      throw new NotFoundException('Audit log record not found');
    }
    return projected;
  }

  async exportForContext(
    ctx: Omit<AuditFieldPolicyContext, 'purpose'>,
    range: { from: Date; to: Date },
  ) {
    const rows = await this.prisma.auditLog.findMany({
      where: {
        ...(ctx.role !== 'PLATFORM_OPERATOR' ? { organizationId: ctx.organizationId ?? '__NONE__' } : {}),
        createdAt: { gte: range.from, lte: range.to },
      },
      orderBy: { createdAt: 'asc' },
      take: 1000,
    });

    return this.applyFieldPolicy(rows, { ...ctx, purpose: 'EXPORT' });
  }

  private async applyFieldPolicy(
    records: AuditLog[],
    ctx: AuditFieldPolicyContext,
  ): Promise<Array<Record<string, unknown>>> {
    const results: Array<Record<string, unknown>> = [];
    const sensitiveFieldsAccessed = new Set<string>();
    const sensitiveRecordIds: string[] = [];

    for (const row of records) {
      const { projected, accessedSensitiveFields } = projectAuditLogRecord(row, ctx);
      if (!projected) continue;
      results.push(projected);

      if (accessedSensitiveFields.length > 0) {
        sensitiveRecordIds.push(row.id);
        accessedSensitiveFields.forEach((f) => sensitiveFieldsAccessed.add(f));
      }
    }

    // Meta-audit every read of sensitive audit fields
    if (sensitiveRecordIds.length > 0) {
      await this.record({
        actor: { type: ctx.role, id: ctx.actorId },
        action: 'audit.sensitive_fields.accessed',
        outcome: 'SUCCESS',
        meta: {
          purpose: ctx.purpose,
          organizationId: ctx.organizationId,
          recordCount: sensitiveRecordIds.length,
          sampleRecordId: sensitiveRecordIds[0],
          fields: Array.from(sensitiveFieldsAccessed),
        },
      });
    }

    return results;
  }
}