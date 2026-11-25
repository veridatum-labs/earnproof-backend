import { AuditLog } from '@prisma/client';

export type AuditPolicyActorRole = 'PLATFORM_OPERATOR' | 'ORG_ADMIN' | 'SUPPORT' | 'ORG_MEMBER';
export type AuditAccessPurpose = 'LIST' | 'DETAIL' | 'EXPORT' | 'SECURITY_INVESTIGATION';

export interface AuditFieldPolicyContext {
  actorId: string;
  role: AuditPolicyActorRole;
  organizationId: string | null;
  purpose: AuditAccessPurpose;
}

const PUBLIC_SAFE_FIELDS: ReadonlyArray<keyof AuditLog> = [
  'id',
  'organizationId',
  'action',
  'resourceType',
  'resourceId',
  'createdAt',
];

const ORG_ADMIN_FIELDS: ReadonlyArray<keyof AuditLog> = [
  ...PUBLIC_SAFE_FIELDS,
  'actorType',
  'actorId',
  'correlationId',
  'parentId',
];

const SUPPORT_FIELDS: ReadonlyArray<keyof AuditLog> = [
  ...PUBLIC_SAFE_FIELDS,
  'correlationId',
];

// Sensitive operator-only fields (tamper chain internals + raw metadata)
const OPERATOR_SENSITIVE_FIELDS: ReadonlyArray<keyof AuditLog> = [
  'metadata',
  'chainKey',
  'sequence',
  'hashVersion',
  'prevHash',
  'hash',
];

// Safe metadata keys an ORG_ADMIN is allowed to read (everything else stripped server-side)
const ORG_ADMIN_SAFE_METADATA_KEYS = new Set([
  'transferId',
  'webhookId',
  'rotatedKeyId',
  'targetOrganizationId',
  'reasonCode',
  'outcome',
]);

export function projectAuditLogRecord(
  record: AuditLog,
  ctx: AuditFieldPolicyContext,
): { projected: Record<string, unknown> | null; accessedSensitiveFields: string[] } {
  // Strict tenant isolation for non-operators
  if (ctx.role !== 'PLATFORM_OPERATOR') {
    if (!ctx.organizationId || record.organizationId !== ctx.organizationId) {
      return { projected: null, accessedSensitiveFields: [] };
    }
  }

  const isMetaAudit = record.action === 'audit.sensitive_fields.accessed';
  const allowSensitive =
    ctx.role === 'PLATFORM_OPERATOR' &&
    !isMetaAudit &&
    (ctx.purpose === 'SECURITY_INVESTIGATION' || ctx.purpose === 'DETAIL');

  let allowed: ReadonlyArray<keyof AuditLog>;
  switch (ctx.role) {
    case 'PLATFORM_OPERATOR':
      allowed = allowSensitive
        ? [...ORG_ADMIN_FIELDS, ...OPERATOR_SENSITIVE_FIELDS]
        : ORG_ADMIN_FIELDS;
      break;
    case 'ORG_ADMIN':
      // Exports strip actorId for data minimization unless explicitly authorized
      allowed =
        ctx.purpose === 'EXPORT'
          ? [...PUBLIC_SAFE_FIELDS, 'actorType', 'correlationId']
          : ORG_ADMIN_FIELDS;
      break;
    case 'SUPPORT':
      allowed = SUPPORT_FIELDS;
      break;
    default:
      allowed = PUBLIC_SAFE_FIELDS;
  }

  const projected: Record<string, unknown> = {};
  const accessedSensitiveFields: string[] = [];

  for (const key of allowed) {
    const value = record[key];
    if (value !== undefined) {
      projected[key] = typeof value === 'bigint' ? value.toString() : value;
      if (allowSensitive && OPERATOR_SENSITIVE_FIELDS.includes(key)) {
        accessedSensitiveFields.push(key);
      }
    }
  }

  // Allow ORG_ADMIN a sanitized allowlisted subset of `metadata` on DETAIL/LIST
  if (
    ctx.role === 'ORG_ADMIN' &&
    ctx.purpose !== 'EXPORT' &&
    record.metadata &&
    typeof record.metadata === 'object' &&
    !Array.isArray(record.metadata)
  ) {
    const safeMeta: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record.metadata as Record<string, unknown>)) {
      if (ORG_ADMIN_SAFE_METADATA_KEYS.has(k)) {
        safeMeta[k] = v;
      }
    }
    if (Object.keys(safeMeta).length > 0) {
      projected.metadata = safeMeta;
    }
  }

  return { projected, accessedSensitiveFields };
}