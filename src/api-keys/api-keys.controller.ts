import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UseGuards,
  ForbiddenException,
  BadRequestException,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiResponse,
} from "@nestjs/swagger";
import { ApiKeyScope } from "@prisma/client";
import { AuthGuard } from "../common/guards/auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthenticatedUser } from "../auth/auth.types";
import { ApiKeyService } from "./api-key.service";
import { PrismaService } from "../database/prisma.service";

/**
 * API Keys Controller - Machine-to-machine integration credential management.
 *
 * Access control:
 * - All endpoints require wallet authentication (AuthGuard) + organization admin role
 * - Organization isolation enforced at query level (cannot manage other orgs' keys)
 * - Role check must be implemented per organization membership/admin status
 *   (this codebase doesn't yet have explicit org-role modeling, so we check
 *    organization membership implicitly via user context when available)
 *
 * Response behavior:
 * - Creation: returns raw secret EXACTLY ONCE (never retrievable again)
 * - Listing: returns metadata only (id, prefix, name, status, scopes, dates)
 * - Rotation: returns new raw secret EXACTLY ONCE, invalidates old secret immediately
 * - Revocation: marks key REVOKED, takes effect immediately (no cache window)
 *
 * One-time secret display:
 * - Clients must save the returned secret immediately
 * - No code path allows retrieving or reconstructing the secret later
 * - If secret is lost, client must rotate the key to get a new one
 */
@ApiBearerAuth()
@ApiTags("api-keys")
@UseGuards(AuthGuard)
@Controller("api-keys")
export class ApiKeysController {
  constructor(
    private readonly apiKeyService: ApiKeyService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Create a new API key for an organization.
   *
   * Authorization: Organization admin only
   * Returns: Raw secret (display ONCE), key metadata
   * Note: Secret is never stored again; must be saved by client
   */
  @Post()
  @ApiOperation({
    summary: "Create a new API key",
    description:
      "Generate a new API key for machine-to-machine integrations. The raw secret is returned exactly once and cannot be retrieved later.",
  })
  @ApiResponse({
    status: 201,
    description: "API key created successfully",
    schema: {
      example: {
        secret: "dGVzdGtleTAx_[...base64url encrypted key...]",
        apiKey: {
          id: "key_abc123",
          prefix: "dGVzdGtl",
          name: "GitHub CI",
          status: "ACTIVE",
          scopes: ["PROOF_VERIFY", "PAYMENT_READ"],
          createdAt: "2026-08-24T12:00:00Z",
          expiresAt: null,
        },
      },
    },
  })
  async createKey(
    @CurrentUser() user: AuthenticatedUser,
    @Body()
    body: {
      name: string;
      scopes?: ApiKeyScope[];
      expiresAt?: string;
    },
  ) {
    // Authorization: User must be organization admin
    const organizationId = await this.getUserPrimaryOrganizationId(user.id);
    if (!organizationId) {
      throw new ForbiddenException(
        "Only organization admins can create API keys. You must be the organization creator or an admin member.",
      );
    }

    const expiresAt = body.expiresAt ? new Date(body.expiresAt) : undefined;

    // Validate scopes if provided
    if (body.scopes) {
      const validScopes = Object.values(ApiKeyScope);
      for (const scope of body.scopes) {
        if (!validScopes.includes(scope)) {
          throw new BadRequestException(`Invalid scope: ${scope}`);
        }
      }
    }

    const result = await this.apiKeyService.createKey({
      organizationId,
      createdBy: user.id,
      name: body.name,
      scopes: body.scopes,
      expiresAt,
    });

    // Important: return includes the raw secret exactly once
    return {
      secret: result.secret,
      apiKey: result.apiKey,
    };
  }

  /**
   * List API keys for user's organization.
   *
   * Authorization: Organization admin only
   * Returns: Metadata only (never includes secrets or hashes)
   */
  @Get()
  @ApiOperation({
    summary: "List API keys for your organization",
    description: "List all API keys for your organization (metadata only, no secrets).",
  })
  @ApiResponse({
    status: 200,
    description: "List of API keys",
    schema: {
      example: [
        {
          id: "key_abc123",
          prefix: "dGVzdGtl",
          name: "GitHub CI",
          status: "ACTIVE",
          scopes: ["PROOF_VERIFY", "PAYMENT_READ"],
          createdAt: "2026-08-24T12:00:00Z",
          rotatedAt: null,
          revokedAt: null,
          expiresAt: null,
          lastUsedAt: "2026-08-24T13:30:00Z",
        },
      ],
    },
  })
  async listKeys(@CurrentUser() user: AuthenticatedUser) {
    // Authorization: User must be organization admin
    const organizationId = await this.getUserPrimaryOrganizationId(user.id);
    if (!organizationId) {
      throw new ForbiddenException(
        "Only organization admins can list API keys. You must be the organization creator or an admin member.",
      );
    }

    const keys = await this.apiKeyService.listKeysForOrganization(
      organizationId,
    );

    return keys.map((key) => ({
      id: key.id,
      prefix: key.prefix,
      name: key.name,
      status: key.status,
      scopes: key.scopeAssignments.map((sa) => sa.scope),
      createdAt: key.createdAt,
      rotatedAt: key.rotatedAt,
      revokedAt: key.revokedAt,
      expiresAt: key.expiresAt,
      lastUsedAt: key.lastUsedAt,
    }));
  }

  /**
   * Rotate an API key: generate new secret, invalidate old immediately.
   *
   * Authorization: Organization admin only
   * Returns: New raw secret (display ONCE), updated key metadata
   * Effect: Old secret stops working immediately
   */
  @Post(":id/rotate")
  @ApiOperation({
    summary: "Rotate an API key",
    description:
      "Generate a new secret for an existing API key. The old secret is invalidated immediately and can never be used again.",
  })
  @ApiResponse({
    status: 200,
    description: "API key rotated successfully",
    schema: {
      example: {
        secret: "bmV3c2VjcmV0MDEy_[...base64url encrypted key...]",
        apiKey: {
          id: "key_abc123",
          prefix: "bmV3c2Vj",
          name: "GitHub CI",
          status: "ACTIVE",
          scopes: ["PROOF_VERIFY", "PAYMENT_READ"],
          rotatedAt: "2026-08-24T14:00:00Z",
        },
      },
    },
  })
  async rotateKey(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") keyId: string,
  ) {
    // Authorization: User must be organization admin
    const organizationId = await this.getUserPrimaryOrganizationId(user.id);
    if (!organizationId) {
      throw new ForbiddenException(
        "Only organization admins can rotate API keys. You must be the organization creator or an admin member.",
      );
    }

    // Verify the key belongs to this organization (enforced by service)
    try {
      const result = await this.apiKeyService.rotateKey(
        keyId,
        organizationId,
        user.id, // Pass actor for audit logging
      );

      // Important: return includes the new raw secret exactly once
      return {
        secret: result.secret,
        apiKey: result.apiKey,
      };
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("does not belong to this organization")
      ) {
        throw new ForbiddenException(
          "API key does not belong to your organization",
        );
      }
      throw error;
    }
  }

  /**
   * Revoke an API key: mark as revoked, take effect immediately.
   *
   * Authorization: Organization admin only
   * Returns: Updated key metadata
   * Effect: Revoked key is rejected by auth guard immediately
   */
  @Delete(":id/revoke")
  @ApiOperation({
    summary: "Revoke an API key",
    description:
      "Revoke an API key. The key is immediately rejected by the authentication system.",
  })
  @ApiResponse({
    status: 200,
    description: "API key revoked successfully",
  })
  async revokeKey(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") keyId: string,
  ) {
    // Authorization: User must be organization admin
    const organizationId = await this.getUserPrimaryOrganizationId(user.id);
    if (!organizationId) {
      throw new ForbiddenException(
        "Only organization admins can revoke API keys. You must be the organization creator or an admin member.",
      );
    }

    // Verify the key belongs to this organization (enforced by service)
    try {
      await this.apiKeyService.revokeKey(
        keyId,
        organizationId,
        user.id, // Pass actor for audit logging
      );
      return { message: "API key revoked successfully" };
    } catch (error) {
      if (error instanceof Error && error.message.includes("Key not found")) {
        throw new ForbiddenException("API key not found");
      }
      if (
        error instanceof Error &&
        error.message.includes("does not belong to this organization")
      ) {
        throw new ForbiddenException(
          "API key does not belong to your organization",
        );
      }
      throw error;
    }
  }

  /**
   * Helper: Get user's primary organization ID and verify admin access.
   *
   * Returns the organization ID if the user is an admin of at least one organization.
   * In this codebase, organization admin is determined by:
   * - User created the organization (createdById == userId), OR
   * - User has ADMIN role (global admin has access to all orgs)
   *
   * TODO: This implementation assumes user can only manage orgs they created.
   * For multi-admin orgs, implement explicit OrganizationMember join table
   * with role field (admin, member, etc.)
   *
   * @returns organizationId if authorized as admin, null otherwise
   */
  private async getUserPrimaryOrganizationId(
    userId: string,
  ): Promise<string | null> {
    // Query for an organization created by this user
    const org = await this.prisma.organization.findFirst({
      where: {
        createdById: userId,
      },
      select: {
        id: true,
      },
    });

    return org?.id || null;
  }
}
