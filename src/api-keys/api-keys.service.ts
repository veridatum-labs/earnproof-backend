import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { randomBytes } from "crypto";
import { sha256 } from "../common/crypto/hash";
import { safeEqual } from "../common/crypto/timing-safe";
import { PrismaService } from "../database/prisma.service";
import { CreateApiKeyDto } from "./dto/create-api-key.dto";

/** Roles that are allowed to manage API keys on behalf of an organization. */
const MANAGER_ROLES = new Set(["ADMIN", "ISSUER", "DEVELOPER"]);

/** Prefix format: ep_<12 random hex chars>_  (non-secret, safe to log/display) */
const PREFIX_BYTES = 6; // 12 hex chars
const SECRET_BYTES = 32; // 256-bit secret

export interface ApiKeyPrincipal {
  keyId: string;
  organizationId: string;
  scopes: string[];
}

@Injectable()
export class ApiKeysService {
  constructor(private readonly prisma: PrismaService) {}

  // ---------------------------------------------------------------------------
  // Management endpoints (require AuthGuard + org membership)
  // ---------------------------------------------------------------------------

  async createApiKey(
    actor: { id: string; role: string },
    organizationId: string,
    dto: CreateApiKeyDto,
  ) {
    await this.assertOrgAccess(actor, organizationId);

    const rawPrefix = randomBytes(PREFIX_BYTES).toString("hex");
    const rawSecret = randomBytes(SECRET_BYTES).toString("hex");
    const rawKey = `ep_${rawPrefix}_${rawSecret}`;

    const keyHash = this.hashKey(rawKey);
    const expiresAt = dto.expiresAt ? new Date(dto.expiresAt) : undefined;

    const created = await this.prisma.apiKey.create({
      data: {
        organizationId,
        createdById: actor.id,
        name: dto.name,
        keyHash,
        keyPrefix: `ep_${rawPrefix}_`,
        scopes: dto.scopes,
        status: ResourceStatus.ACTIVE,
        expiresAt,
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        status: true,
        expiresAt: true,
        createdAt: true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actor.id,
        action: "api_key.created",
        resourceType: "api_key",
        resourceId: created.id,
        metadata: {
          name: dto.name,
          organizationId,
          scopes: dto.scopes,
          expiresAt: expiresAt?.toISOString() ?? null,
        },
      },
    });

    // Raw key material is returned ONCE and never persisted.
    return { ...created, secret: rawKey };
  }

  async listApiKeys(
    actor: { id: string; role: string },
    organizationId: string,
  ) {
    await this.assertOrgAccess(actor, organizationId);

    return this.prisma.apiKey.findMany({
      where: {
        organizationId,
        status: { not: ResourceStatus.DELETED },
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        status: true,
        lastUsedAt: true,
        expiresAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
  }

  async rotateApiKey(
    actor: { id: string; role: string },
    organizationId: string,
    keyId: string,
  ) {
    await this.assertOrgAccess(actor, organizationId);

    const existing = await this.findKeyInOrg(keyId, organizationId);

    const rawPrefix = randomBytes(PREFIX_BYTES).toString("hex");
    const rawSecret = randomBytes(SECRET_BYTES).toString("hex");
    const rawKey = `ep_${rawPrefix}_${rawSecret}`;

    const keyHash = this.hashKey(rawKey);

    const updated = await this.prisma.apiKey.update({
      where: { id: keyId },
      data: {
        keyHash,
        keyPrefix: `ep_${rawPrefix}_`,
        status: ResourceStatus.ACTIVE,
        revokedAt: null,
        lastUsedAt: null,
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        scopes: true,
        status: true,
        expiresAt: true,
        createdAt: true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actor.id,
        action: "api_key.rotated",
        resourceType: "api_key",
        resourceId: keyId,
        metadata: {
          organizationId,
          previousStatus: existing.status,
        },
      },
    });

    return { ...updated, secret: rawKey };
  }

  async revokeApiKey(
    actor: { id: string; role: string },
    organizationId: string,
    keyId: string,
  ) {
    await this.assertOrgAccess(actor, organizationId);
    await this.findKeyInOrg(keyId, organizationId);

    const revoked = await this.prisma.apiKey.update({
      where: { id: keyId },
      data: {
        status: ResourceStatus.REVOKED,
        revokedAt: new Date(),
      },
      select: {
        id: true,
        name: true,
        keyPrefix: true,
        status: true,
        revokedAt: true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actor.id,
        action: "api_key.revoked",
        resourceType: "api_key",
        resourceId: keyId,
        metadata: { organizationId },
      },
    });

    return revoked;
  }

  // ---------------------------------------------------------------------------
  // Authentication (called by ApiKeyGuard)
  // ---------------------------------------------------------------------------

  /**
   * Validates a raw API key presented in the `x-api-key` header.
   * Returns the principal on success or throws UnauthorizedException.
   * Never logs the raw key material.
   */
  async authenticate(rawKey: string): Promise<ApiKeyPrincipal> {
    if (!rawKey || typeof rawKey !== "string") {
      throw new UnauthorizedException("Missing API key");
    }

    const keyHash = this.hashKey(rawKey);

    const record = await this.prisma.apiKey.findUnique({
      where: { keyHash },
      select: {
        id: true,
        organizationId: true,
        keyHash: true,
        scopes: true,
        status: true,
        expiresAt: true,
      },
    });

    if (!record) {
      throw new UnauthorizedException("Invalid API key");
    }

    // Timing-safe comparison to guard against hash oracle attacks
    if (!safeEqual(record.keyHash, keyHash)) {
      throw new UnauthorizedException("Invalid API key");
    }

    if (record.status !== ResourceStatus.ACTIVE) {
      throw new UnauthorizedException("API key is revoked or inactive");
    }

    if (record.expiresAt && record.expiresAt <= new Date()) {
      throw new UnauthorizedException("API key has expired");
    }

    // Fire-and-forget last-used update; never store raw key material
    void this.prisma.apiKey
      .update({
        where: { id: record.id },
        data: { lastUsedAt: new Date() },
      })
      .catch(() => {
        // Non-critical; do not propagate
      });

    return {
      keyId: record.id,
      organizationId: record.organizationId,
      scopes: record.scopes,
    };
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private hashKey(rawKey: string): string {
    return `sha256:${sha256(rawKey)}`;
  }

  private async assertOrgAccess(
    actor: { id: string; role: string },
    organizationId: string,
  ) {
    if (!MANAGER_ROLES.has(actor.role)) {
      throw new ForbiddenException(
        "Insufficient role to manage API keys",
      );
    }

    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { id: true, status: true },
    });

    if (!org || org.status === ResourceStatus.DELETED) {
      throw new NotFoundException("Organization not found");
    }

    if (org.status !== ResourceStatus.ACTIVE) {
      throw new ForbiddenException("Organization is not active");
    }
  }

  private async findKeyInOrg(keyId: string, organizationId: string) {
    const key = await this.prisma.apiKey.findFirst({
      where: { id: keyId, organizationId },
      select: { id: true, status: true },
    });

    if (!key) {
      throw new NotFoundException("API key not found");
    }

    return key;
  }
}
