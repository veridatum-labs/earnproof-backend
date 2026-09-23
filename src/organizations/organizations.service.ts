import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { AuthenticatedUser } from "../auth/auth.types";
import { PrismaService } from "../database/prisma.service";
import { OptimisticLockHelper } from "../common/concurrency";
import { CreateOrganizationDto } from "./dto/create-organization.dto";
import { ListOrganizationsDto } from "./dto/list-organizations.dto";
import { OrganizationResponseDto } from "./dto/organization-response.dto";
import { UpdateOrganizationDto } from "./dto/update-organization.dto";

@Injectable()
export class OrganizationsService {
  constructor(private readonly prisma: PrismaService) {}

  async createOrganization(
    user: AuthenticatedUser,
    input: CreateOrganizationDto,
  ): Promise<OrganizationResponseDto> {
    if (user.role !== "ADMIN") {
      throw new ForbiddenException("Only admins can create organizations");
    }

    // Check if slug already exists
    const existing = await this.prisma.organization.findUnique({
      where: { slug: input.slug },
    });

    if (existing) {
      throw new ConflictException(
        `Organization with slug "${input.slug}" already exists`,
      );
    }

    const org = await this.prisma.organization.create({
      data: {
        name: input.name,
        slug: input.slug,
        website: input.website || null,
        createdById: user.id,
        status: ResourceStatus.PENDING,
      },
    });

    // Log audit event
    await this.createAuditLog(user, "CREATE", "Organization", org.id, {
      name: org.name,
      slug: org.slug,
      website: org.website,
    });

    return this.toResponseDto(org);
  }

  async updateOrganization(
    user: AuthenticatedUser,
    organizationId: string,
    input: UpdateOrganizationDto,
  ): Promise<OrganizationResponseDto> {
    const org = await this.getVisibleOrganization(user, organizationId);

    // Check revision before applying update
    OptimisticLockHelper.checkRevision({
      resourceType: "Organization",
      resourceId: organizationId,
      expectedRevision: input.revision,
      currentRevision: org.revision,
    });

    // Atomically update organization and increment revision in a transaction
    const updated = await this.prisma.$transaction(async (tx) => {
      const result = await tx.organization.updateMany({
        where: {
          id: organizationId,
          revision: org.revision, // Double-check that revision hasn't changed
        },
        data: {
          ...(input.name && { name: input.name }),
          ...(input.website !== undefined && { website: input.website || null }),
          revision: OptimisticLockHelper.incrementRevision(org.revision),
        },
      });

      // If no rows were updated, the revision check failed (concurrent write)
      if (result.count === 0) {
        const current = await tx.organization.findUnique({
          where: { id: organizationId },
        });
        throw new ConflictException(
          JSON.stringify({
            code: "CONFLICT",
            message: `Organization has been modified. Expected revision ${org.revision}, but current revision is ${current?.revision}. Please refresh and retry.`,
            currentRevision: current?.revision,
          }),
        );
      }

      // Fetch the updated record
      return tx.organization.findUnique({
        where: { id: organizationId },
      });
    });

    // Log audit event
    await this.createAuditLog(user, "UPDATE", "Organization", organizationId, {
      changes: input,
    });

    return this.toResponseDto(updated);
  }

  async getOrganization(
    user: AuthenticatedUser,
    organizationId: string,
  ): Promise<OrganizationResponseDto> {
    const org = await this.getVisibleOrganization(user, organizationId);
    const issuerCount = await this.prisma.issuer.count({
      where: { organizationId },
    });

    return {
      ...this.toResponseDto(org),
      issuerCount,
    };
  }

  async listOrganizations(
    user: AuthenticatedUser,
    query: ListOrganizationsDto,
  ): Promise<{
    items: OrganizationResponseDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    const page = query.page || 1;
    const limit = Math.min(query.limit || 20, 100);
    const skip = (page - 1) * limit;

    const where: any = {};
    if (query.status) {
      where.status = query.status;
    }

    // Non-admins see organizations they created OR are members of
    if (user.role !== "ADMIN") {
      where.OR = [
        { createdById: user.id },
        {
          memberships: {
            some: {
              userId: user.id,
            },
          },
        },
      ];
    }

    const [items, total] = await Promise.all([
      this.prisma.organization.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: "desc" },
      }),
      this.prisma.organization.count({ where }),
    ]);

    const response = await Promise.all(
      items.map(async (org) => {
        const issuerCount = await this.prisma.issuer.count({
          where: { organizationId: org.id },
        });
        return {
          ...this.toResponseDto(org),
          issuerCount,
        };
      }),
    );

    return {
      items: response,
      total,
      page,
      limit,
    };
  }

  async getOrganizationById(organizationId: string) {
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
    });

    if (!org) {
      throw new NotFoundException(
        `Organization with ID "${organizationId}" not found`,
      );
    }

    return org;
  }

  /**
   * Get an organization with visibility checks based on user role and membership.
   * Admins can see all organizations.
   * Non-admins can only see organizations where they are members or creators.
   * Scoped query prevents permission oracle attacks.
   */
  async getVisibleOrganization(
    user: AuthenticatedUser,
    organizationId: string,
  ) {
    // For admins, no membership check needed
    if (user.role === "ADMIN") {
      const org = await this.prisma.organization.findUnique({
        where: { id: organizationId },
      });
      if (!org) throw new NotFoundException("Organization not found");
      return org;
    }

    // For non-admins: check if they are a member OR creator of the organization
    const org = await this.prisma.organization.findFirst({
      where: {
        id: organizationId,
        OR: [
          // Creator (implicit owner from legacy model)
          { createdById: user.id },
          // Explicit member through membership table
          {
            memberships: {
              some: {
                userId: user.id,
              },
            },
          },
        ],
      },
      include: {
        memberships: {
          where: { userId: user.id },
          select: { role: true },
        },
      },
    });

    if (!org) throw new NotFoundException("Organization not found");
    return org;
  }

  private toResponseDto(org: any): OrganizationResponseDto {
    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      website: org.website,
      status: org.status,
      revision: org.revision,
      createdById: org.createdById,
      createdAt: org.createdAt,
      updatedAt: org.updatedAt,
    };
  }

  private createAuditLog(
    user: AuthenticatedUser,
    action: string,
    resourceType: string,
    resourceId: string,
    metadata: any,
  ) {
    return this.prisma.auditLog.create({
      data: {
        actorId: user.id,
        actorType: "User",
        action,
        resourceType,
        resourceId,
        metadata,
        createdAt: new Date(),
      },
    });
  }
}
