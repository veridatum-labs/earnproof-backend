import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { OrganizationRole } from "@prisma/client";
import { AuthenticatedUser } from "../auth/auth.types";
import { PrismaService } from "../database/prisma.service";
import { SessionService } from "../auth/session.service";
import { InviteMemberDto } from "./dto/invite-member.dto";
import { UpdateMemberRoleDto } from "./dto/update-member-role.dto";
import { MembershipResponseDto } from "./dto/membership-response.dto";

@Injectable()
export class OrganizationMembershipsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly sessionService: SessionService,
  ) {}

  /**
   * Invite a user to an organization with a specific role.
   * Only OWNER and ADMIN members can invite others.
   * Cross-organization isolation: membership is scoped to the organization and user.
   */
  async inviteMember(
    user: AuthenticatedUser,
    organizationId: string,
    input: InviteMemberDto,
  ): Promise<MembershipResponseDto> {
    // 1. Verify requester has permission to invite (OWNER or ADMIN)
    await this.checkMembershipPermission(user.id, organizationId, [
      "OWNER",
      "ADMIN",
    ]);

    // 2. Verify organization exists
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
    });
    if (!org) {
      throw new NotFoundException("Organization not found");
    }

    // 3. Find or create user by wallet address
    const targetUser = await this.prisma.user.findUnique({
      where: { walletAddress: input.walletAddress },
    });

    if (!targetUser) {
      throw new NotFoundException(
        `User with wallet address "${input.walletAddress}" not found`,
      );
    }

    // 4. Check if membership already exists (unique constraint on org_id + user_id)
    const existingMembership = await this.prisma.organizationMembership.findUnique(
      {
        where: {
          organizationId_userId: {
            organizationId,
            userId: targetUser.id,
          },
        },
      },
    );

    if (existingMembership) {
      throw new ConflictException(
        "User is already a member of this organization",
      );
    }

    // 5. Create membership record
    const membership = await this.prisma.organizationMembership.create({
      data: {
        organizationId,
        userId: targetUser.id,
        role: input.role,
      },
    });

    // 6. Log audit event
    await this.createAuditLog(user, "INVITE_MEMBER", organizationId, {
      targetUserId: targetUser.id,
      walletAddress: input.walletAddress,
      role: input.role,
    });

    return this.toResponseDto(membership, targetUser.walletAddress);
  }

  /**
   * List all members of an organization with their roles.
   * Only organization members can list members (requester must have valid membership).
   * Cross-organization isolation: returns only members scoped to the organization.
   */
  async listMembers(
    user: AuthenticatedUser,
    organizationId: string,
    query: { page?: number; limit?: number } = {},
  ): Promise<{
    items: MembershipResponseDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    // 1. Verify requester is a member of the organization
    await this.checkMembershipPermission(user.id, organizationId, [
      "OWNER",
      "ADMIN",
      "READER",
    ]);

    // 2. Verify organization exists
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
    });
    if (!org) {
      throw new NotFoundException("Organization not found");
    }

    const page = query.page || 1;
    const limit = Math.min(query.limit || 20, 100);
    const skip = (page - 1) * limit;

    // 3. Query memberships scoped to organization (cross-org isolation)
    const [memberships, total] = await Promise.all([
      this.prisma.organizationMembership.findMany({
        where: { organizationId },
        skip,
        take: limit,
        include: {
          organization: false,
        },
        orderBy: { createdAt: "desc" },
      }),
      this.prisma.organizationMembership.count({
        where: { organizationId },
      }),
    ]);

    // 4. Fetch wallet addresses for each member
    const userIds = memberships.map((m) => m.userId);
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, walletAddress: true },
    });

    const userMap = new Map(users.map((u) => [u.id, u.walletAddress]));

    return {
      items: memberships.map((m) =>
        this.toResponseDto(m, userMap.get(m.userId) || ""),
      ),
      total,
      page,
      limit,
    };
  }

  /**
   * Update a member's role in the organization.
   * Only OWNER and ADMIN members can update roles.
   * Enforces last-owner protection: the last owner cannot demote themselves unless a successor owner exists.
   * Invalidates sessions on role change to prevent stale authorization.
   * Cross-organization isolation: membership must be scoped to the organization.
   */
  async updateMemberRole(
    user: AuthenticatedUser,
    organizationId: string,
    userId: string,
    input: UpdateMemberRoleDto,
  ): Promise<MembershipResponseDto> {
    // 1. Verify requester has permission to update roles (OWNER or ADMIN)
    await this.checkMembershipPermission(user.id, organizationId, [
      "OWNER",
      "ADMIN",
    ]);

    // 2. Verify organization exists
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
    });
    if (!org) {
      throw new NotFoundException("Organization not found");
    }

    // 3. Find target membership (cross-org isolation: must be in same org)
    const targetMembership = await this.prisma.organizationMembership.findUnique(
      {
        where: {
          organizationId_userId: {
            organizationId,
            userId,
          },
        },
      },
    );

    if (!targetMembership) {
      throw new NotFoundException("Member not found in this organization");
    }

    // 4. Last-owner protection: if target is the last OWNER and being demoted,
    //    check if there's a successor owner
    if (
      targetMembership.role === "OWNER" &&
      input.role !== "OWNER"
    ) {
      const ownerCount = await this.prisma.organizationMembership.count({
        where: {
          organizationId,
          role: "OWNER",
        },
      });

      if (ownerCount === 1) {
        throw new ForbiddenException(
          "Cannot demote the last owner. Promote another member to owner first.",
        );
      }
    }

    // 5. Update membership role
    const updatedMembership = await this.prisma.organizationMembership.update({
      where: {
        organizationId_userId: {
          organizationId,
          userId,
        },
      },
      data: {
        role: input.role,
      },
    });

    // 6. Invalidate all sessions for the target user to force re-auth with new role
    await this.sessionService.revokeAll(userId);

    // 7. Log audit event
    const targetUser = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { walletAddress: true },
    });
    await this.createAuditLog(user, "UPDATE_MEMBER_ROLE", organizationId, {
      targetUserId: userId,
      walletAddress: targetUser?.walletAddress,
      oldRole: targetMembership.role,
      newRole: input.role,
    });

    return this.toResponseDto(
      updatedMembership,
      targetUser?.walletAddress || "",
    );
  }

  /**
   * Remove a member from an organization.
   * Only OWNER and ADMIN members can remove members.
   * Enforces last-owner protection: the last owner cannot remove themselves.
   * Invalidates sessions on removal to prevent stale authorization.
   * Cross-organization isolation: membership must be scoped to the organization.
   */
  async removeMember(
    user: AuthenticatedUser,
    organizationId: string,
    userId: string,
  ): Promise<{ success: boolean }> {
    // 1. Verify requester has permission to remove members (OWNER or ADMIN)
    await this.checkMembershipPermission(user.id, organizationId, [
      "OWNER",
      "ADMIN",
    ]);

    // 2. Verify organization exists
    const org = await this.prisma.organization.findUnique({
      where: { id: organizationId },
    });
    if (!org) {
      throw new NotFoundException("Organization not found");
    }

    // 3. Find target membership (cross-org isolation: must be in same org)
    const targetMembership = await this.prisma.organizationMembership.findUnique(
      {
        where: {
          organizationId_userId: {
            organizationId,
            userId,
          },
        },
      },
    );

    if (!targetMembership) {
      throw new NotFoundException("Member not found in this organization");
    }

    // 4. Last-owner protection: if target is the last OWNER, prevent removal
    if (targetMembership.role === "OWNER") {
      const ownerCount = await this.prisma.organizationMembership.count({
        where: {
          organizationId,
          role: "OWNER",
        },
      });

      if (ownerCount === 1) {
        throw new ForbiddenException(
          "Cannot remove the last owner. Promote another member to owner first.",
        );
      }
    }

    // 5. Delete membership record
    await this.prisma.organizationMembership.delete({
      where: {
        organizationId_userId: {
          organizationId,
          userId,
        },
      },
    });

    // 6. Invalidate all sessions for the removed user
    await this.sessionService.revokeAll(userId);

    // 7. Log audit event
    const targetUser = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { walletAddress: true },
    });
    await this.createAuditLog(user, "REMOVE_MEMBER", organizationId, {
      targetUserId: userId,
      walletAddress: targetUser?.walletAddress,
      role: targetMembership.role,
    });

    return { success: true };
  }

  /**
   * Internal helper: Check if a user has a specific membership role in an organization.
   * Throws ForbiddenException if the user is not a member or lacks required role.
   * Cross-organization isolation: ensures membership is scoped to the organization.
   */
  private async checkMembershipPermission(
    userId: string,
    organizationId: string,
    allowedRoles: OrganizationRole[],
  ): Promise<void> {
    const membership = await this.prisma.organizationMembership.findUnique({
      where: {
        organizationId_userId: {
          organizationId,
          userId,
        },
      },
    });

    if (!membership) {
      throw new ForbiddenException(
        "You are not a member of this organization",
      );
    }

    if (!allowedRoles.includes(membership.role)) {
      throw new ForbiddenException(
        `This action requires one of these roles: ${allowedRoles.join(", ")}`,
      );
    }
  }

  /**
   * Convert membership record to response DTO with wallet address.
   */
  private toResponseDto(
    membership: any,
    walletAddress: string,
  ): MembershipResponseDto {
    return {
      id: membership.id,
      organizationId: membership.organizationId,
      userId: membership.userId,
      walletAddress,
      role: membership.role,
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
    };
  }

  /**
   * Create audit log entry for membership operations.
   */
  private createAuditLog(
    user: AuthenticatedUser,
    action: string,
    organizationId: string,
    metadata: any,
  ) {
    return this.prisma.auditLog.create({
      data: {
        actorId: user.id,
        actorType: "User",
        action,
        resourceType: "OrganizationMembership",
        resourceId: organizationId,
        metadata: {
          ...metadata,
          organizationId,
        },
        createdAt: new Date(),
      },
    });
  }
}
