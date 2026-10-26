import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import {
  OrganizationMemberRole,
  Prisma,
  ResourceStatus,
  RoleChangeRequestStatus,
  SecurityNotificationSeverity,
  SecurityNotificationType,
} from "@prisma/client";
import { AuthenticatedUser } from "../../auth/auth.types";
import { DESTRUCTIVE_ACTIONS, RecentAuthService } from "../../auth/recent-auth.service";
import { SessionService } from "../../auth/session.service";
import { PrismaService } from "../../database/prisma.service";
import { RoleApprovalPolicyService } from "../role-approval-policy/role-approval-policy.service";
import { evaluateRoleChange } from "../role-approval-policy/role-approval-policy.rules";
import { ApproveRoleChangeRequestDto } from "./dto/approve-role-change-request.dto";
import { CancelRoleChangeRequestDto } from "./dto/cancel-role-change-request.dto";
import { CreateRoleChangeRequestDto } from "./dto/create-role-change-request.dto";
import { ListRoleChangeRequestsDto } from "./dto/list-role-change-requests.dto";
import { RejectRoleChangeRequestDto } from "./dto/reject-role-change-request.dto";
import {
  RoleChangeApprovalRecordDto,
  RoleChangeRequestResponseDto,
} from "./dto/role-change-request-response.dto";

const ROLE_RANK: Record<OrganizationMemberRole, number> = {
  OWNER: 4,
  ADMIN: 3,
  MEMBER: 2,
  VIEWER: 1,
};

@Injectable()
export class RoleChangeRequestsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly policies: RoleApprovalPolicyService,
    private readonly recentAuthService: RecentAuthService,
    private readonly sessions: SessionService,
  ) {}

  /**
   * Create a new role change request.
   *
   * Only ACTIVE organization owners or admins (or platform admins) can submit
   * requests. Self-role changes are allowed to be requested (e.g. promoting self),
   * but self-approval will be strictly forbidden on the approval path.
   */
  async create(
    user: AuthenticatedUser,
    organizationId: string,
    dto: CreateRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    const org = await this.authorize(user, organizationId, "ADMIN");
    if (org.archivedAt) {
      throw new ConflictException(
        "Organization is archived; role changes cannot be requested.",
      );
    }

    const member = await this.prisma.organizationMember.findUnique({
      where: { id: dto.memberId },
      include: { user: true },
    });

    if (!member || member.organizationId !== organizationId) {
      throw new NotFoundException(`Organization member ${dto.memberId} not found`);
    }

    if (member.role === dto.proposedRole) {
      throw new BadRequestException(
        `Target member already holds the ${dto.proposedRole} role.`,
      );
    }

    // Demoting final owner check
    if (member.role === "OWNER" && dto.proposedRole !== "OWNER") {
      const ownerCount = await this.prisma.organizationMember.count({
        where: { organizationId, role: "OWNER", status: ResourceStatus.ACTIVE },
      });
      if (ownerCount === 1) {
        throw new ForbiddenException(
          "Cannot demote the final owner. Assign a new owner first.",
        );
      }
    }

    // Concurrency check on creation: caller can specify expected revision
    if (
      dto.expectedMemberRevision !== undefined &&
      dto.expectedMemberRevision !== member.revision
    ) {
      throw new ConflictException(
        `Stale membership version: expected revision ${dto.expectedMemberRevision} ` +
          `but current revision is ${member.revision}.`,
      );
    }

    // Prevent duplicate open pending requests for the same member in this org
    const activePending = await this.prisma.organizationRoleChangeRequest.findFirst({
      where: {
        organizationId,
        targetMemberId: member.id,
        status: RoleChangeRequestStatus.PENDING,
        expiresAt: { gt: new Date() },
      },
    });

    if (activePending) {
      throw new ConflictException(
        "An active role change request is already pending for this member.",
      );
    }

    const policy = await this.policies.getActive(user, organizationId);
    const evaluation = evaluateRoleChange(policy, member.role, dto.proposedRole);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + policy.approvalExpiryMinutes * 60_000);

    const request = await this.prisma.organizationRoleChangeRequest.create({
      data: {
        organizationId,
        requesterId: user.id,
        targetUserId: member.userId,
        targetMemberId: member.id,
        oldRole: member.role,
        proposedRole: dto.proposedRole,
        justification: dto.justification,
        status: RoleChangeRequestStatus.PENDING,
        expectedMemberRevision: member.revision,
        policyVersion: policy.version,
        requiredApprovals: evaluation.requiredApprovals,
        expiresAt,
      },
      include: {
        approvals: true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "User",
        actorId: user.id,
        action: "organization.role_change.requested",
        resourceType: "OrganizationRoleChangeRequest",
        resourceId: request.id,
        organizationId,
        metadata: {
          requestId: request.id,
          targetUserId: member.userId,
          targetMemberId: member.id,
          oldRole: member.role,
          proposedRole: dto.proposedRole,
          justification: dto.justification,
          policyVersion: policy.version,
          requiredApprovals: evaluation.requiredApprovals,
          expiresAt: expiresAt.toISOString(),
        },
      },
    });

    await this.prisma.securityNotification.create({
      data: {
        organizationId,
        userId: member.userId,
        type: SecurityNotificationType.ROLE_CHANGE_REQUESTED,
        severity: SecurityNotificationSeverity.HIGH,
        title: "Privileged role change requested",
        summary: `Role change requested from ${member.role} to ${dto.proposedRole} by ${user.id}`,
        data: {
          requestId: request.id,
          requesterId: user.id,
          targetUserId: member.userId,
          oldRole: member.role,
          proposedRole: dto.proposedRole,
          justification: dto.justification,
          expiresAt: expiresAt.toISOString(),
        },
        retainUntil: new Date(Date.now() + 90 * 86400 * 1000),
      },
    });

    return this.toResponse(request);
  }

  /**
   * Get a role change request by ID.
   * Any ACTIVE organization member (or platform admin) can read requests.
   */
  async get(
    user: AuthenticatedUser,
    organizationId: string,
    requestId: string,
  ): Promise<RoleChangeRequestResponseDto> {
    await this.authorize(user, organizationId, "VIEWER");

    const request = await this.prisma.organizationRoleChangeRequest.findUnique({
      where: { id: requestId },
      include: { approvals: true },
    });

    if (!request || request.organizationId !== organizationId) {
      throw new NotFoundException(`Role change request ${requestId} not found`);
    }

    return this.toResponse(request);
  }

  /**
   * List role change requests for an organization.
   */
  async list(
    user: AuthenticatedUser,
    organizationId: string,
    query: ListRoleChangeRequestsDto,
  ): Promise<{ items: RoleChangeRequestResponseDto[]; total: number; page: number; limit: number }> {
    await this.authorize(user, organizationId, "VIEWER");

    const page = query.page ?? 1;
    const limit = query.limit ?? 20;
    const skip = (page - 1) * limit;

    const where: Prisma.OrganizationRoleChangeRequestWhereInput = {
      organizationId,
      ...(query.status ? { status: query.status } : {}),
      ...(query.targetUserId ? { targetUserId: query.targetUserId } : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.organizationRoleChangeRequest.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: "desc" },
        include: { approvals: true },
      }),
      this.prisma.organizationRoleChangeRequest.count({ where }),
    ]);

    return {
      items: items.map((r) => this.toResponse(r)),
      total,
      page,
      limit,
    };
  }

  /**
   * Approve a pending role change request.
   *
   * Enforces:
   * - Separation of duties: requester cannot approve (self-approval prohibited),
   *   target cannot approve (target approval prohibited).
   * - Configurable independent approval: requires eligible approver role per policy,
   *   and distinct approvers if requiredApprovals > 1.
   * - Recent-auth requirement: consumes single-use assertion token when required by policy.
   * - Stale membership detection: target member must still exist, be ACTIVE, and have
   *   exact matching revision.
   * - Transactional apply: applies role change, increments revision, writes audit log,
   *   and creates security notification atomically.
   * - Concurrency: exactly one terminal decision wins under concurrent requests.
   */
  async approve(
    user: AuthenticatedUser,
    organizationId: string,
    requestId: string,
    dto: ApproveRoleChangeRequestDto,
    recentAuthToken?: string,
    origin?: string,
  ): Promise<RoleChangeRequestResponseDto> {
    const org = await this.authorize(user, organizationId, "VIEWER");
    if (org.archivedAt) {
      throw new ConflictException(
        "Organization is archived; role changes cannot be approved.",
      );
    }

    const request = await this.prisma.organizationRoleChangeRequest.findUnique({
      where: { id: requestId },
      include: { approvals: true },
    });

    if (!request || request.organizationId !== organizationId) {
      throw new NotFoundException(`Role change request ${requestId} not found`);
    }

    const now = new Date();

    if (request.status !== RoleChangeRequestStatus.PENDING) {
      throw new ConflictException(
        `Role change request already has a terminal decision: ${request.status}`,
      );
    }

    if (now >= request.expiresAt) {
      throw new ConflictException(
        "Role change request has expired and can no longer be decided.",
      );
    }

    // Separation of duties: Self-approval prohibited
    if (user.id === request.requesterId) {
      throw new ForbiddenException(
        "Self-approval is prohibited: the requester cannot approve their own role change request.",
      );
    }

    // Separation of duties: Target approval prohibited
    if (user.id === request.targetUserId) {
      throw new ForbiddenException(
        "Target approval is prohibited: the member whose role changes may never approve the change.",
      );
    }

    // Separation of duties: Distinct approvers
    if (request.approvals.some((a) => a.approverId === user.id)) {
      throw new ConflictException("You have already approved this role change request.");
    }

    // Evaluate active policy
    const policy = await this.policies.getActive(user, organizationId);
    const evaluation = evaluateRoleChange(policy, request.oldRole, request.proposedRole);

    // Verify caller role eligibility
    if (user.role !== "ADMIN") {
      const approverMembership = await this.prisma.organizationMember.findUnique({
        where: { organizationId_userId: { organizationId, userId: user.id } },
      });
      if (!approverMembership || approverMembership.status !== ResourceStatus.ACTIVE) {
        throw new ForbiddenException("Approver is not an active organization member.");
      }
      if (!evaluation.eligibleApproverRoles.includes(approverMembership.role)) {
        throw new ForbiddenException(
          `Approval requires one of the following roles: ${evaluation.eligibleApproverRoles.join(", ")}`,
        );
      }
    }

    // Enforce recent-auth if required by policy
    if (evaluation.requireRecentAuth) {
      if (!recentAuthToken || recentAuthToken.trim() === "") {
        throw new UnauthorizedException(
          "A valid recent-auth assertion is required for this operation. " +
            "Re-authenticate via POST /auth/verify and include the assertion token in the X-Recent-Auth header.",
        );
      }
      await this.recentAuthService.consume({
        token: recentAuthToken,
        action: DESTRUCTIVE_ACTIONS.ROLE_CHANGE_APPROVE,
        resourceId: requestId,
        origin: origin ?? "null",
      });
    }

    // Check target member standing & stale membership revision before transaction
    const targetMember = await this.prisma.organizationMember.findUnique({
      where: { id: request.targetMemberId },
    });

    if (!targetMember || targetMember.organizationId !== organizationId) {
      throw new ConflictException("Target member no longer exists in this organization.");
    }

    if (targetMember.status !== ResourceStatus.ACTIVE) {
      throw new ConflictException("Target member is no longer active.");
    }

    if (targetMember.revision !== request.expectedMemberRevision) {
      throw new ConflictException(
        `Stale membership version: expected revision ${request.expectedMemberRevision} ` +
          `but current revision is ${targetMember.revision}. Member standing has changed.`,
      );
    }

    // Demoting final owner check
    if (targetMember.role === "OWNER" && request.proposedRole !== "OWNER") {
      const ownerCount = await this.prisma.organizationMember.count({
        where: { organizationId, role: "OWNER", status: ResourceStatus.ACTIVE },
      });
      if (ownerCount === 1) {
        throw new ForbiddenException(
          "Cannot demote the final owner. Assign a new owner first.",
        );
      }
    }

    const currentApprovalsCount = request.approvals.length + 1;
    const isTerminalApproval = currentApprovalsCount >= request.requiredApprovals;

    // Apply inside transaction
    const result = await this.prisma.$transaction(async (tx) => {
      if (isTerminalApproval) {
        // Atomic conditional update on the request to ensure exactly ONE terminal decision wins
        const updateRes = await tx.organizationRoleChangeRequest.updateMany({
          where: {
            id: requestId,
            status: RoleChangeRequestStatus.PENDING,
            expiresAt: { gt: now },
          },
          data: {
            status: RoleChangeRequestStatus.APPROVED,
            decidedById: user.id,
            decidedAt: now,
            appliedAt: now,
            decisionReason: dto.reason ?? null,
          },
        });

        if (updateRes.count === 0) {
          const fresh = await tx.organizationRoleChangeRequest.findUnique({
            where: { id: requestId },
          });
          if (fresh && fresh.status !== RoleChangeRequestStatus.PENDING) {
            throw new ConflictException(
              `Request already has a terminal decision: ${fresh.status}`,
            );
          }
          throw new ConflictException(
            "Request has expired and can no longer be decided.",
          );
        }

        // Re-check target member revision in transaction
        const memberInTx = await tx.organizationMember.findUnique({
          where: { id: request.targetMemberId },
        });

        if (!memberInTx || memberInTx.revision !== request.expectedMemberRevision) {
          throw new ConflictException(
            "Stale membership version: member standing changed during approval.",
          );
        }

        // Transactionally apply the role change and increment revision
        await tx.organizationMember.update({
          where: { id: request.targetMemberId },
          data: {
            role: request.proposedRole,
            revision: { increment: 1 },
          },
        });

        // Record approval
        await tx.organizationRoleChangeApproval.create({
          data: {
            requestId,
            approverId: user.id,
            reason: dto.reason ?? null,
          },
        });

        // Audit log
        await tx.auditLog.create({
          data: {
            actorType: "User",
            actorId: user.id,
            action: "organization.role_change.applied",
            resourceType: "OrganizationMember",
            resourceId: request.targetMemberId,
            organizationId,
            metadata: {
              requestId: request.id,
              targetUserId: request.targetUserId,
              targetMemberId: request.targetMemberId,
              oldRole: request.oldRole,
              newRole: request.proposedRole,
              requesterId: request.requesterId,
              approverId: user.id,
              justification: request.justification,
              decisionReason: dto.reason ?? null,
            },
          },
        });

        // Security notification
        await tx.securityNotification.create({
          data: {
            organizationId,
            userId: request.targetUserId,
            type: SecurityNotificationType.ROLE_CHANGE_APPROVED,
            severity: SecurityNotificationSeverity.HIGH,
            title: "Privileged role change applied",
            summary: `Role changed from ${request.oldRole} to ${request.proposedRole} following dual-control approval`,
            data: {
              requestId: request.id,
              targetUserId: request.targetUserId,
              oldRole: request.oldRole,
              newRole: request.proposedRole,
              requesterId: request.requesterId,
              approverId: user.id,
            },
            retainUntil: new Date(Date.now() + 90 * 86400 * 1000),
          },
        });
      } else {
        // Multi-approval policy: intermediate approval
        const fresh = await tx.organizationRoleChangeRequest.findFirst({
          where: {
            id: requestId,
            status: RoleChangeRequestStatus.PENDING,
            expiresAt: { gt: now },
          },
        });

        if (!fresh) {
          throw new ConflictException(
            "Request is no longer pending or has expired.",
          );
        }

        await tx.organizationRoleChangeApproval.create({
          data: {
            requestId,
            approverId: user.id,
            reason: dto.reason ?? null,
          },
        });

        await tx.auditLog.create({
          data: {
            actorType: "User",
            actorId: user.id,
            action: "organization.role_change.approved",
            resourceType: "OrganizationRoleChangeRequest",
            resourceId: requestId,
            organizationId,
            metadata: {
              requestId,
              approverId: user.id,
              approvalCount: currentApprovalsCount,
              requiredApprovals: request.requiredApprovals,
            },
          },
        });
      }

      return tx.organizationRoleChangeRequest.findUniqueOrThrow({
        where: { id: requestId },
        include: { approvals: true },
      });
    });

    // Invalidate target user sessions after commit
    if (isTerminalApproval) {
      await this.sessions.revokeAll(request.targetUserId);
    }

    return this.toResponse(result);
  }

  /**
   * Reject a pending role change request.
   */
  async reject(
    user: AuthenticatedUser,
    organizationId: string,
    requestId: string,
    dto: RejectRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    const org = await this.authorize(user, organizationId, "VIEWER");
    if (org.archivedAt) {
      throw new ConflictException(
        "Organization is archived; role changes cannot be rejected.",
      );
    }

    const request = await this.prisma.organizationRoleChangeRequest.findUnique({
      where: { id: requestId },
      include: { approvals: true },
    });

    if (!request || request.organizationId !== organizationId) {
      throw new NotFoundException(`Role change request ${requestId} not found`);
    }

    const now = new Date();

    if (request.status !== RoleChangeRequestStatus.PENDING) {
      throw new ConflictException(
        `Request already has a terminal decision: ${request.status}`,
      );
    }

    if (now >= request.expiresAt) {
      throw new ConflictException(
        "Request has expired and can no longer be decided.",
      );
    }

    // Verify approver role eligibility
    const policy = await this.policies.getActive(user, organizationId);
    const evaluation = evaluateRoleChange(policy, request.oldRole, request.proposedRole);

    if (user.role !== "ADMIN") {
      const approverMembership = await this.prisma.organizationMember.findUnique({
        where: { organizationId_userId: { organizationId, userId: user.id } },
      });
      if (!approverMembership || approverMembership.status !== ResourceStatus.ACTIVE) {
        throw new ForbiddenException("Approver is not an active organization member.");
      }
      if (!evaluation.eligibleApproverRoles.includes(approverMembership.role)) {
        throw new ForbiddenException(
          `Rejection requires one of the following roles: ${evaluation.eligibleApproverRoles.join(", ")}`,
        );
      }
    }

    // Atomic conditional update
    const res = await this.prisma.organizationRoleChangeRequest.updateMany({
      where: {
        id: requestId,
        status: RoleChangeRequestStatus.PENDING,
        expiresAt: { gt: now },
      },
      data: {
        status: RoleChangeRequestStatus.REJECTED,
        decidedById: user.id,
        decidedAt: now,
        decisionReason: dto.reason,
      },
    });

    if (res.count === 0) {
      const fresh = await this.prisma.organizationRoleChangeRequest.findUnique({
        where: { id: requestId },
      });
      if (fresh && fresh.status !== RoleChangeRequestStatus.PENDING) {
        throw new ConflictException(
          `Request already has a terminal decision: ${fresh.status}`,
        );
      }
      throw new ConflictException(
        "Request has expired and can no longer be decided.",
      );
    }

    await this.prisma.auditLog.create({
      data: {
        actorType: "User",
        actorId: user.id,
        action: "organization.role_change.rejected",
        resourceType: "OrganizationRoleChangeRequest",
        resourceId: requestId,
        organizationId,
        metadata: {
          requestId,
          decidedById: user.id,
          reason: dto.reason,
        },
      },
    });

    await this.prisma.securityNotification.create({
      data: {
        organizationId,
        userId: request.requesterId,
        type: SecurityNotificationType.ROLE_CHANGE_REJECTED,
        severity: SecurityNotificationSeverity.INFO,
        title: "Role change request rejected",
        summary: `Role change request from ${request.oldRole} to ${request.proposedRole} was rejected`,
        data: {
          requestId,
          rejectedById: user.id,
          reason: dto.reason,
        },
        retainUntil: new Date(Date.now() + 90 * 86400 * 1000),
      },
    });

    const updated = await this.prisma.organizationRoleChangeRequest.findUniqueOrThrow({
      where: { id: requestId },
      include: { approvals: true },
    });

    return this.toResponse(updated);
  }

  /**
   * Cancel a pending role change request.
   * Only the requester, an organization OWNER, or a platform ADMIN can cancel.
   */
  async cancel(
    user: AuthenticatedUser,
    organizationId: string,
    requestId: string,
    dto: CancelRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    await this.authorize(user, organizationId, "VIEWER");

    const request = await this.prisma.organizationRoleChangeRequest.findUnique({
      where: { id: requestId },
      include: { approvals: true },
    });

    if (!request || request.organizationId !== organizationId) {
      throw new NotFoundException(`Role change request ${requestId} not found`);
    }

    const now = new Date();

    if (request.status !== RoleChangeRequestStatus.PENDING) {
      throw new ConflictException(
        `Request already has a terminal decision: ${request.status}`,
      );
    }

    if (now >= request.expiresAt) {
      throw new ConflictException(
        "Request has expired and cannot be cancelled.",
      );
    }

    // Authorization: Requester or OWNER or platform ADMIN
    let canCancel = user.role === "ADMIN" || user.id === request.requesterId;
    if (!canCancel) {
      const membership = await this.prisma.organizationMember.findUnique({
        where: { organizationId_userId: { organizationId, userId: user.id } },
      });
      canCancel = membership?.role === "OWNER" && membership.status === ResourceStatus.ACTIVE;
    }

    if (!canCancel) {
      throw new ForbiddenException(
        "Only the requester or an organization owner can cancel this role change request.",
      );
    }

    // Atomic conditional update
    const res = await this.prisma.organizationRoleChangeRequest.updateMany({
      where: {
        id: requestId,
        status: RoleChangeRequestStatus.PENDING,
        expiresAt: { gt: now },
      },
      data: {
        status: RoleChangeRequestStatus.CANCELLED,
        decidedById: user.id,
        decidedAt: now,
        decisionReason: dto.reason ?? "Cancelled by requester",
      },
    });

    if (res.count === 0) {
      const fresh = await this.prisma.organizationRoleChangeRequest.findUnique({
        where: { id: requestId },
      });
      if (fresh && fresh.status !== RoleChangeRequestStatus.PENDING) {
        throw new ConflictException(
          `Request already has a terminal decision: ${fresh.status}`,
        );
      }
      throw new ConflictException(
        "Request has expired and can no longer be decided.",
      );
    }

    await this.prisma.auditLog.create({
      data: {
        actorType: "User",
        actorId: user.id,
        action: "organization.role_change.cancelled",
        resourceType: "OrganizationRoleChangeRequest",
        resourceId: requestId,
        organizationId,
        metadata: {
          requestId,
          cancelledById: user.id,
          reason: dto.reason ?? "Cancelled by requester",
        },
      },
    });

    const updated = await this.prisma.organizationRoleChangeRequest.findUniqueOrThrow({
      where: { id: requestId },
      include: { approvals: true },
    });

    return this.toResponse(updated);
  }

  private async authorize(
    user: AuthenticatedUser,
    organizationId: string,
    minimum: OrganizationMemberRole,
  ): Promise<{ archivedAt: Date | null }> {
    const organization = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { archivedAt: true, deletedAt: true },
    });

    if (!organization || organization.deletedAt) {
      throw new NotFoundException(`Organization ${organizationId} not found`);
    }

    if (user.role === "ADMIN") return organization;

    const membership = await this.prisma.organizationMember.findUnique({
      where: { organizationId_userId: { organizationId, userId: user.id } },
      select: { role: true, status: true },
    });

    if (!membership || membership.status !== "ACTIVE") {
      throw new ForbiddenException("You are not a member of this organization");
    }

    if (ROLE_RANK[membership.role] < ROLE_RANK[minimum]) {
      throw new ForbiddenException(
        `This action requires the ${minimum} organization role`,
      );
    }

    return organization;
  }

  private toResponse(
    row: Prisma.OrganizationRoleChangeRequestGetPayload<{
      include: { approvals: true };
    }>,
  ): RoleChangeRequestResponseDto {
    const now = new Date();
    const effectiveStatus =
      row.status === RoleChangeRequestStatus.PENDING && now >= row.expiresAt
        ? RoleChangeRequestStatus.EXPIRED
        : row.status;

    const approvals: RoleChangeApprovalRecordDto[] = (row.approvals ?? []).map(
      (a) => ({
        id: a.id,
        approverId: a.approverId,
        reason: a.reason,
        createdAt: a.createdAt.toISOString(),
      }),
    );

    return {
      id: row.id,
      organizationId: row.organizationId,
      requesterId: row.requesterId,
      targetUserId: row.targetUserId,
      targetMemberId: row.targetMemberId,
      oldRole: row.oldRole,
      proposedRole: row.proposedRole,
      justification: row.justification,
      status: effectiveStatus,
      expectedMemberRevision: row.expectedMemberRevision,
      policyVersion: row.policyVersion,
      requiredApprovals: row.requiredApprovals,
      currentApprovalsCount: approvals.length,
      expiresAt: row.expiresAt.toISOString(),
      decidedById: row.decidedById,
      decidedAt: row.decidedAt?.toISOString() ?? null,
      decisionReason: row.decisionReason,
      appliedAt: row.appliedAt?.toISOString() ?? null,
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
      approvals,
    };
  }
}
