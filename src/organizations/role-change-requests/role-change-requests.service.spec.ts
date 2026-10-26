import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
} from "@nestjs/common";
import {
  OrganizationMemberRole,
  ResourceStatus,
  RoleChangeRequestStatus,
} from "@prisma/client";
import { AuthenticatedUser } from "../../auth/auth.types";
import { DESTRUCTIVE_ACTIONS, RecentAuthService } from "../../auth/recent-auth.service";
import { SessionService } from "../../auth/session.service";
import { PrismaService } from "../../database/prisma.service";
import { RoleApprovalPolicyService } from "../role-approval-policy/role-approval-policy.service";
import { RoleChangeRequestsService } from "./role-change-requests.service";

const ORG_A = "org-a";
const ORG_B = "org-b";

function createUser(id: string, role: "ADMIN" | "WORKER" = "WORKER"): AuthenticatedUser {
  return { id, role, walletAddress: `G-${id}`, walletHash: `h-${id}` } as AuthenticatedUser;
}

const platformAdmin = createUser("platform-admin", "ADMIN");
const ownerUser = createUser("owner-user");
const adminUser = createUser("admin-user");
const targetUser = createUser("target-user");
const otherAdmin = createUser("other-admin");
const regularMember = createUser("regular-member");
const outsider = createUser("outsider");

describe("RoleChangeRequestsService", () => {
  let service: RoleChangeRequestsService;
  let prisma: any;
  let policies: any;
  let recentAuth: any;
  let sessions: any;

  // In-memory state
  let requests: any[];
  let approvals: any[];
  let members: Record<string, any>;
  let organizations: Record<string, any>;
  let auditLogs: any[];
  let securityNotifications: any[];

  function setupState() {
    requests = [];
    approvals = [];
    auditLogs = [];
    securityNotifications = [];

    organizations = {
      [ORG_A]: { id: ORG_A, name: "Org A", status: ResourceStatus.ACTIVE, archivedAt: null, deletedAt: null },
      [ORG_B]: { id: ORG_B, name: "Org B", status: ResourceStatus.ACTIVE, archivedAt: null, deletedAt: null },
    };

    members = {
      "member-owner": {
        id: "member-owner",
        organizationId: ORG_A,
        userId: ownerUser.id,
        role: "OWNER",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: ownerUser.walletAddress },
      },
      "member-admin": {
        id: "member-admin",
        organizationId: ORG_A,
        userId: adminUser.id,
        role: "ADMIN",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: adminUser.walletAddress },
      },
      "member-other-admin": {
        id: "member-other-admin",
        organizationId: ORG_A,
        userId: otherAdmin.id,
        role: "ADMIN",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: otherAdmin.walletAddress },
      },
      "member-target": {
        id: "member-target",
        organizationId: ORG_A,
        userId: targetUser.id,
        role: "MEMBER",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: targetUser.walletAddress },
      },
      "member-regular": {
        id: "member-regular",
        organizationId: ORG_A,
        userId: regularMember.id,
        role: "VIEWER",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: regularMember.walletAddress },
      },
      "member-org-b": {
        id: "member-org-b",
        organizationId: ORG_B,
        userId: outsider.id,
        role: "OWNER",
        status: ResourceStatus.ACTIVE,
        revision: 0,
        user: { walletAddress: outsider.walletAddress },
      },
    };
  }

  beforeEach(() => {
    setupState();

    let nextRequestId = 1;
    let nextApprovalId = 1;

    prisma = {
      organization: {
        findUnique: jest.fn(async ({ where }: any) => organizations[where.id] ?? null),
      },
      organizationMember: {
        findUnique: jest.fn(async ({ where }: any) => {
          if (where.id) return members[where.id] ?? null;
          if (where.organizationId_userId) {
            return (
              Object.values(members).find(
                (m) =>
                  m.organizationId === where.organizationId_userId.organizationId &&
                  m.userId === where.organizationId_userId.userId,
              ) ?? null
            );
          }
          return null;
        }),
        count: jest.fn(async ({ where }: any) => {
          return Object.values(members).filter((m) => {
            if (m.organizationId !== where.organizationId) return false;
            if (where.role && m.role !== where.role) return false;
            if (where.status && m.status !== where.status) return false;
            return true;
          }).length;
        }),
        update: jest.fn(async ({ where, data }: any) => {
          const m = members[where.id];
          if (!m) throw new Error("Member not found in update");
          if (data.role) m.role = data.role;
          if (data.revision?.increment) m.revision += data.revision.increment;
          return { ...m };
        }),
      },
      organizationRoleChangeRequest: {
        create: jest.fn(async ({ data }: any) => {
          const row = {
            ...data,
            id: `req-${nextRequestId++}`,
            createdAt: new Date(),
            updatedAt: new Date(),
            approvals: [],
          };
          requests.push(row);
          return { ...row };
        }),
        findUnique: jest.fn(async ({ where }: any) => {
          const row = requests.find((r) => r.id === where.id);
          if (!row) return null;
          const reqApprovals = approvals.filter((a) => a.requestId === row.id);
          return { ...row, approvals: reqApprovals };
        }),
        findUniqueOrThrow: jest.fn(async ({ where }: any) => {
          const row = requests.find((r) => r.id === where.id);
          if (!row) throw new NotFoundException();
          const reqApprovals = approvals.filter((a) => a.requestId === row.id);
          return { ...row, approvals: reqApprovals };
        }),
        findFirst: jest.fn(async ({ where }: any) => {
          const row = requests.find((r) => {
            if (where.id && r.id !== where.id) return false;
            if (where.organizationId && r.organizationId !== where.organizationId) return false;
            if (where.targetMemberId && r.targetMemberId !== where.targetMemberId) return false;
            if (where.status && r.status !== where.status) return false;
            if (where.expiresAt?.gt && !(r.expiresAt > where.expiresAt.gt)) return false;
            return true;
          });
          if (!row) return null;
          const reqApprovals = approvals.filter((a) => a.requestId === row.id);
          return { ...row, approvals: reqApprovals };
        }),
        findMany: jest.fn(async ({ where }: any) => {
          return requests
            .filter((r) => {
              if (where.organizationId && r.organizationId !== where.organizationId) return false;
              if (where.status && r.status !== where.status) return false;
              if (where.targetUserId && r.targetUserId !== where.targetUserId) return false;
              return true;
            })
            .map((r) => ({
              ...r,
              approvals: approvals.filter((a) => a.requestId === r.id),
            }));
        }),
        count: jest.fn(async ({ where }: any) => {
          return requests.filter((r) => {
            if (where.organizationId && r.organizationId !== where.organizationId) return false;
            if (where.status && r.status !== where.status) return false;
            if (where.targetUserId && r.targetUserId !== where.targetUserId) return false;
            return true;
          }).length;
        }),
        updateMany: jest.fn(async ({ where, data }: any) => {
          const row = requests.find((r) => {
            if (r.id !== where.id) return false;
            if (where.status && r.status !== where.status) return false;
            if (where.expiresAt?.gt && !(r.expiresAt > where.expiresAt.gt)) return false;
            return true;
          });
          if (!row) return { count: 0 };
          Object.assign(row, data, { updatedAt: new Date() });
          return { count: 1 };
        }),
      },
      organizationRoleChangeApproval: {
        create: jest.fn(async ({ data }: any) => {
          if (approvals.some((a) => a.requestId === data.requestId && a.approverId === data.approverId)) {
            const err = new Error("Unique constraint failed");
            (err as any).code = "P2002";
            throw err;
          }
          const app = { ...data, id: `app-${nextApprovalId++}`, createdAt: new Date() };
          approvals.push(app);
          return { ...app };
        }),
      },
      auditLog: {
        create: jest.fn(async ({ data }: any) => {
          auditLogs.push(data);
          return { id: "audit-1", ...data };
        }),
      },
      securityNotification: {
        create: jest.fn(async ({ data }: any) => {
          securityNotifications.push(data);
          return { id: "notif-1", ...data };
        }),
      },
      $transaction: jest.fn(async (callback: any) => callback(prisma)),
    };

    policies = {
      getActive: jest.fn().mockResolvedValue({
        protectedRoles: ["OWNER", "ADMIN"],
        approverRoles: ["OWNER", "ADMIN"],
        requiredApprovals: 1,
        approvalExpiryMinutes: 60,
        ownerChangesRequireOwnerApproval: true,
        requireRecentAuth: true,
        version: 1,
      }),
    };

    recentAuth = {
      consume: jest.fn().mockResolvedValue({ userId: ownerUser.id }),
    };

    sessions = {
      revokeAll: jest.fn().mockResolvedValue(undefined),
    };

    service = new RoleChangeRequestsService(
      prisma as unknown as PrismaService,
      policies as unknown as RoleApprovalPolicyService,
      recentAuth as unknown as RecentAuthService,
      sessions as unknown as SessionService,
    );
  });

  // ---------------------------------------------------------------------------
  // Creation
  // ---------------------------------------------------------------------------
  describe("create()", () => {
    it("persists role-change request with requester, target, old and proposed role, justification, and expiry", async () => {
      const res = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Promotion for managing deployments",
      });

      expect(res).toMatchObject({
        organizationId: ORG_A,
        requesterId: adminUser.id,
        targetUserId: targetUser.id,
        targetMemberId: "member-target",
        oldRole: "MEMBER",
        proposedRole: "ADMIN",
        justification: "Promotion for managing deployments",
        status: RoleChangeRequestStatus.PENDING,
        expectedMemberRevision: 0,
        requiredApprovals: 1,
        policyVersion: 1,
      });

      expect(new Date(res.expiresAt).getTime()).toBeGreaterThan(Date.now());
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: "organization.role_change.requested",
            resourceType: "OrganizationRoleChangeRequest",
          }),
        }),
      );
      expect(prisma.securityNotification.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            type: "ROLE_CHANGE_REQUESTED",
            userId: targetUser.id,
          }),
        }),
      );
    });

    it("rejects creation if target already holds proposed role", async () => {
      await expect(
        service.create(adminUser, ORG_A, {
          memberId: "member-target",
          proposedRole: "MEMBER",
          justification: "Redundant change",
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it("rejects creation if caller has insufficient role (< ADMIN)", async () => {
      await expect(
        service.create(regularMember, ORG_A, {
          memberId: "member-target",
          proposedRole: "ADMIN",
          justification: "Self request",
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects creation if organization is archived", async () => {
      organizations[ORG_A].archivedAt = new Date();

      await expect(
        service.create(adminUser, ORG_A, {
          memberId: "member-target",
          proposedRole: "ADMIN",
          justification: "Archived test",
        }),
      ).rejects.toThrow(ConflictException);
    });

    it("rejects creation if demoting the final owner", async () => {
      await expect(
        service.create(adminUser, ORG_A, {
          memberId: "member-owner",
          proposedRole: "ADMIN",
          justification: "Demote owner",
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects creation when expected revision is stale", async () => {
      await expect(
        service.create(adminUser, ORG_A, {
          memberId: "member-target",
          proposedRole: "ADMIN",
          justification: "Stale revision check",
          expectedMemberRevision: 99,
        }),
      ).rejects.toThrow(ConflictException);
    });

    it("rejects creation if an active pending request already exists for this member", async () => {
      await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "First request",
      });

      await expect(
        service.create(adminUser, ORG_A, {
          memberId: "member-target",
          proposedRole: "OWNER",
          justification: "Second request",
        }),
      ).rejects.toThrow(ConflictException);
    });
  });

  // ---------------------------------------------------------------------------
  // Reading, Listing & Tenant Isolation
  // ---------------------------------------------------------------------------
  describe("get() and list()", () => {
    it("returns request details for active members", async () => {
      const created = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Read test",
      });

      const fetched = await service.get(regularMember, ORG_A, created.id);
      expect(fetched.id).toBe(created.id);
    });

    it("enforces tenant isolation on get (request from Org B viewed in Org A yields 404)", async () => {
      const created = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Isolation test",
      });

      await expect(service.get(outsider, ORG_B, created.id)).rejects.toThrow(NotFoundException);
    });

    it("reports status as EXPIRED if pending request has passed expiresAt", async () => {
      const created = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Expiry check",
      });

      // Move expiry to the past
      requests[0].expiresAt = new Date(Date.now() - 1000);

      const fetched = await service.get(adminUser, ORG_A, created.id);
      expect(fetched.status).toBe(RoleChangeRequestStatus.EXPIRED);
    });

    it("lists requests with pagination and status filter", async () => {
      await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "List test 1",
      });

      const list = await service.list(adminUser, ORG_A, { status: RoleChangeRequestStatus.PENDING });
      expect(list.total).toBe(1);
      expect(list.items).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // Approval
  // ---------------------------------------------------------------------------
  describe("approve()", () => {
    let pendingRequest: any;

    beforeEach(async () => {
      pendingRequest = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Ready for approval",
      });
    });

    it("applies approved changes transactionally with audit and security notifications", async () => {
      const res = await service.approve(
        ownerUser,
        ORG_A,
        pendingRequest.id,
        { reason: "Confirmed skills" },
        "valid-recent-auth-token",
        "https://app.test",
      );

      expect(res.status).toBe(RoleChangeRequestStatus.APPROVED);
      expect(res.decidedById).toBe(ownerUser.id);
      expect(res.decisionReason).toBe("Confirmed skills");

      // Verify member role updated and revision incremented
      const updatedTarget = members["member-target"];
      expect(updatedTarget.role).toBe("ADMIN");
      expect(updatedTarget.revision).toBe(1);

      // Verify audit log
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: "organization.role_change.applied",
            resourceId: "member-target",
            actorId: ownerUser.id,
          }),
        }),
      );

      // Verify security notification
      expect(prisma.securityNotification.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            type: "ROLE_CHANGE_APPROVED",
            userId: targetUser.id,
          }),
        }),
      );

      // Verify session invalidation
      expect(sessions.revokeAll).toHaveBeenCalledWith(targetUser.id);

      // Verify recent auth consumed
      expect(recentAuth.consume).toHaveBeenCalledWith({
        token: "valid-recent-auth-token",
        action: DESTRUCTIVE_ACTIONS.ROLE_CHANGE_APPROVE,
        resourceId: pendingRequest.id,
        origin: "https://app.test",
      });
    });

    it("rejects self-approval (acceptance criteria: self-approval is rejected)", async () => {
      await expect(
        service.approve(
          adminUser, // Same as requester
          ORG_A,
          pendingRequest.id,
          { reason: "Self approval attempt" },
          "tok",
        ),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects target approval (member whose role is changing cannot approve)", async () => {
      // Temporarily give targetUser an ADMIN membership to test duty separation
      members["member-target"].role = "ADMIN";

      await expect(
        service.approve(
          targetUser, // Target user
          ORG_A,
          pendingRequest.id,
          { reason: "Target self approval attempt" },
          "tok",
        ),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects approval by user with non-approver role (e.g. regular member)", async () => {
      await expect(
        service.approve(
          regularMember,
          ORG_A,
          pendingRequest.id,
          {},
          "tok",
        ),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects approval when recent-auth is missing and required by policy", async () => {
      await expect(
        service.approve(
          ownerUser,
          ORG_A,
          pendingRequest.id,
          {},
          undefined, // Missing token
        ),
      ).rejects.toThrow(UnauthorizedException);
    });

    it("allows approval without recent-auth when policy has requireRecentAuth: false", async () => {
      policies.getActive.mockResolvedValueOnce({
        protectedRoles: ["OWNER", "ADMIN"],
        approverRoles: ["OWNER", "ADMIN"],
        requiredApprovals: 1,
        approvalExpiryMinutes: 60,
        ownerChangesRequireOwnerApproval: true,
        requireRecentAuth: false,
        version: 1,
      });

      const res = await service.approve(
        ownerUser,
        ORG_A,
        pendingRequest.id,
        {},
        undefined, // No token needed
      );

      expect(res.status).toBe(RoleChangeRequestStatus.APPROVED);
      expect(recentAuth.consume).not.toHaveBeenCalled();
    });

    it("rejects approval if membership version is stale (acceptance criteria: stale membership versions are rejected)", async () => {
      // Change target member revision
      members["member-target"].revision = 2;

      await expect(
        service.approve(
          ownerUser,
          ORG_A,
          pendingRequest.id,
          {},
          "tok",
        ),
      ).rejects.toThrow(ConflictException);

      // Verify role was NOT updated
      expect(members["member-target"].role).toBe("MEMBER");
    });

    it("rejects approval if target member was removed", async () => {
      delete members["member-target"];

      await expect(
        service.approve(
          ownerUser,
          ORG_A,
          pendingRequest.id,
          {},
          "tok",
        ),
      ).rejects.toThrow(ConflictException);
    });

    it("rejects approval if request has expired", async () => {
      requests[0].expiresAt = new Date(Date.now() - 5000);

      await expect(
        service.approve(
          ownerUser,
          ORG_A,
          pendingRequest.id,
          {},
          "tok",
        ),
      ).rejects.toThrow(ConflictException);
    });

    it("supports multi-approval policy and requires distinct approvers", async () => {
      // Create request with requiredApprovals = 2
      policies.getActive.mockResolvedValue({
        protectedRoles: ["OWNER", "ADMIN"],
        approverRoles: ["OWNER", "ADMIN"],
        requiredApprovals: 2,
        approvalExpiryMinutes: 60,
        ownerChangesRequireOwnerApproval: true,
        requireRecentAuth: false,
        version: 1,
      });

      const multiReq = await service.create(adminUser, ORG_A, {
        memberId: "member-regular",
        proposedRole: "ADMIN",
        justification: "Multi approval test",
      });

      // First approval from ownerUser
      const step1 = await service.approve(ownerUser, ORG_A, multiReq.id, { reason: "Approve 1" });
      expect(step1.status).toBe(RoleChangeRequestStatus.PENDING);
      expect(step1.currentApprovalsCount).toBe(1);
      expect(members["member-regular"].role).toBe("VIEWER"); // Not changed yet

      // Attempt second approval by same approver -> rejected
      await expect(
        service.approve(ownerUser, ORG_A, multiReq.id, { reason: "Duplicate" }),
      ).rejects.toThrow(ConflictException);

      // Second distinct approval from otherAdmin -> satisfies threshold, applies change
      const step2 = await service.approve(otherAdmin, ORG_A, multiReq.id, { reason: "Approve 2" });
      expect(step2.status).toBe(RoleChangeRequestStatus.APPROVED);
      expect(step2.currentApprovalsCount).toBe(2);
      expect(members["member-regular"].role).toBe("ADMIN"); // Applied!
    });
  });

  // ---------------------------------------------------------------------------
  // Rejection
  // ---------------------------------------------------------------------------
  describe("reject()", () => {
    let pendingRequest: any;

    beforeEach(async () => {
      pendingRequest = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Subject to rejection",
      });
    });

    it("rejects request and creates audit and notification", async () => {
      const res = await service.reject(ownerUser, ORG_A, pendingRequest.id, {
        reason: "Position already filled",
      });

      expect(res.status).toBe(RoleChangeRequestStatus.REJECTED);
      expect(res.decidedById).toBe(ownerUser.id);
      expect(res.decisionReason).toBe("Position already filled");
      expect(members["member-target"].role).toBe("MEMBER"); // Role unchanged

      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: "organization.role_change.rejected",
          }),
        }),
      );
    });

    it("rejects decision on already terminal request", async () => {
      await service.reject(ownerUser, ORG_A, pendingRequest.id, { reason: "First" });

      await expect(
        service.reject(otherAdmin, ORG_A, pendingRequest.id, { reason: "Second" }),
      ).rejects.toThrow(ConflictException);
    });
  });

  // ---------------------------------------------------------------------------
  // Cancellation
  // ---------------------------------------------------------------------------
  describe("cancel()", () => {
    let pendingRequest: any;

    beforeEach(async () => {
      pendingRequest = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "May be cancelled",
      });
    });

    it("allows requester to cancel their own request", async () => {
      const res = await service.cancel(adminUser, ORG_A, pendingRequest.id, {
        reason: "Requested in error",
      });

      expect(res.status).toBe(RoleChangeRequestStatus.CANCELLED);
      expect(res.decidedById).toBe(adminUser.id);
      expect(res.decisionReason).toBe("Requested in error");
    });

    it("allows organization owner to cancel a request", async () => {
      const res = await service.cancel(ownerUser, ORG_A, pendingRequest.id, {
        reason: "Owner override",
      });

      expect(res.status).toBe(RoleChangeRequestStatus.CANCELLED);
    });

    it("denies cancellation by unauthorized member", async () => {
      await expect(
        service.cancel(otherAdmin, ORG_A, pendingRequest.id, {}),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects cancellation on an expired request", async () => {
      requests[0].expiresAt = new Date(Date.now() - 1000);

      await expect(
        service.cancel(adminUser, ORG_A, pendingRequest.id, {}),
      ).rejects.toThrow(ConflictException);
    });
  });

  // ---------------------------------------------------------------------------
  // Concurrency & Conflicting Decisions (Acceptance Criteria)
  // ---------------------------------------------------------------------------
  describe("concurrency & conflicting decisions", () => {
    let pendingRequest: any;

    beforeEach(async () => {
      pendingRequest = await service.create(adminUser, ORG_A, {
        memberId: "member-target",
        proposedRole: "ADMIN",
        justification: "Concurrency test",
      });
    });

    it("exactly one terminal decision wins under concurrent requests (approve vs reject)", async () => {
      // Simulate race condition where updateMany for rejection misses because approve won first
      const approvePromise = service.approve(
        ownerUser,
        ORG_A,
        pendingRequest.id,
        { reason: "Approved first" },
        "tok",
      );

      const rejectPromise = service.reject(
        otherAdmin,
        ORG_A,
        pendingRequest.id,
        { reason: "Reject raced" },
      );

      const results = await Promise.allSettled([approvePromise, rejectPromise]);

      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(ConflictException);
    });

    it("exactly one terminal decision wins under concurrent requests (approve vs cancel)", async () => {
      const approvePromise = service.approve(
        ownerUser,
        ORG_A,
        pendingRequest.id,
        { reason: "Approved" },
        "tok",
      );

      const cancelPromise = service.cancel(
        adminUser,
        ORG_A,
        pendingRequest.id,
        { reason: "Cancelled" },
      );

      const results = await Promise.allSettled([approvePromise, cancelPromise]);

      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(ConflictException);
    });

    it("replaying an approval after a terminal decision is rejected with 409 Conflict", async () => {
      await service.approve(
        ownerUser,
        ORG_A,
        pendingRequest.id,
        { reason: "Approved" },
        "tok",
      );

      await expect(
        service.approve(
          ownerUser,
          ORG_A,
          pendingRequest.id,
          { reason: "Replayed" },
          "tok",
        ),
      ).rejects.toThrow(ConflictException);
    });
  });
});
