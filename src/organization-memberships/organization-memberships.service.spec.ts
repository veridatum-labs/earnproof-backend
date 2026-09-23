import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { OrganizationRole } from "@prisma/client";
import { Test, TestingModule } from "@nestjs/testing";
import { PrismaService } from "../database/prisma.service";
import { SessionService } from "../auth/session.service";
import { OrganizationMembershipsService } from "./organization-memberships.service";

describe("OrganizationMembershipsService", () => {
  let service: OrganizationMembershipsService;
  let prisma: PrismaService;
  let sessionService: SessionService;

  const mockUser = {
    id: "user-1",
    walletAddress: "GOWNER1111111111111111111111111111111111111111111111111",
    role: "ADMIN",
    sessionId: "session-1",
  };

  const mockMember = {
    id: "user-2",
    walletAddress: "GMEMBER11111111111111111111111111111111111111111111111",
    role: "ISSUER",
    sessionId: "session-2",
  };

  const mockOrganization = {
    id: "org-1",
    name: "Test Org",
    slug: "test-org",
    createdById: mockUser.id,
    status: "ACTIVE",
  };

  const mockOwnerMembership = {
    id: "membership-1",
    organizationId: "org-1",
    userId: mockUser.id,
    role: "OWNER" as OrganizationRole,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  const mockAdminMembership = {
    id: "membership-2",
    organizationId: "org-1",
    userId: mockMember.id,
    role: "ADMIN" as OrganizationRole,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrganizationMembershipsService,
        {
          provide: PrismaService,
          useValue: {
            organizationMembership: {
              create: jest.fn(),
              findUnique: jest.fn(),
              findMany: jest.fn(),
              count: jest.fn(),
              update: jest.fn(),
              delete: jest.fn(),
            },
            organization: {
              findUnique: jest.fn(),
            },
            user: {
              findUnique: jest.fn(),
              findMany: jest.fn(),
            },
            auditLog: {
              create: jest.fn(),
            },
          },
        },
        {
          provide: SessionService,
          useValue: {
            revokeAll: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<OrganizationMembershipsService>(
      OrganizationMembershipsService,
    );
    prisma = module.get<PrismaService>(PrismaService);
    sessionService = module.get<SessionService>(SessionService);
  });

  describe("inviteMember", () => {
    it("should invite a member with specified role when requester is OWNER", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(null); // membership already exists check
      jest
        .spyOn(prisma.organizationMembership, "create")
        .mockResolvedValueOnce(mockAdminMembership);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      const result = await service.inviteMember(
        mockUser,
        "org-1",
        {
          walletAddress: mockMember.walletAddress,
          role: "ADMIN",
        },
      );

      expect(result.id).toBe(mockAdminMembership.id);
      expect(result.role).toBe("ADMIN");
      expect(result.walletAddress).toBe(mockMember.walletAddress);
      expect(prisma.organizationMembership.create).toHaveBeenCalledWith({
        data: {
          organizationId: "org-1",
          userId: mockMember.id,
          role: "ADMIN",
        },
      });
    });

    it("should reject when requester is not OWNER or ADMIN", async () => {
      const readerMembership = {
        ...mockOwnerMembership,
        userId: mockMember.id,
        role: "READER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(readerMembership); // permission check fails

      await expect(
        service.inviteMember(mockMember, "org-1", {
          walletAddress: "GNEWUSER11111111111111111111111111111111111111111111111",
          role: "READER",
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should reject when organization does not exist", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check passes
      jest.spyOn(prisma.organization, "findUnique").mockResolvedValueOnce(null);

      await expect(
        service.inviteMember(mockUser, "nonexistent", {
          walletAddress: mockMember.walletAddress,
          role: "ADMIN",
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("should reject when target user does not exist", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check passes
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest.spyOn(prisma.user, "findUnique").mockResolvedValueOnce(null);

      await expect(
        service.inviteMember(mockUser, "org-1", {
          walletAddress: "GUNKNOWN11111111111111111111111111111111111111111111111",
          role: "ADMIN",
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("should reject when user is already a member", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // user already member

      await expect(
        service.inviteMember(mockUser, "org-1", {
          walletAddress: mockMember.walletAddress,
          role: "ADMIN",
        }),
      ).rejects.toThrow(ConflictException);
    });

    it("should create audit log on successful invite", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(null); // not already member
      jest
        .spyOn(prisma.organizationMembership, "create")
        .mockResolvedValueOnce(mockAdminMembership);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      await service.inviteMember(mockUser, "org-1", {
        walletAddress: mockMember.walletAddress,
        role: "ADMIN",
      });

      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          actorId: mockUser.id,
          action: "INVITE_MEMBER",
          resourceType: "OrganizationMembership",
          resourceId: "org-1",
          metadata: expect.objectContaining({
            targetUserId: mockMember.id,
            role: "ADMIN",
          }),
        }),
      });
    });
  });

  describe("listMembers", () => {
    it("should list members when requester is a member", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findMany")
        .mockResolvedValueOnce([mockOwnerMembership, mockAdminMembership]);
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(2);
      jest
        .spyOn(prisma.user, "findMany")
        .mockResolvedValueOnce([
          { id: mockUser.id, walletAddress: mockUser.walletAddress },
          { id: mockMember.id, walletAddress: mockMember.walletAddress },
        ]);

      const result = await service.listMembers(mockUser, "org-1");

      expect(result.items).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(20);
      expect(result.items[0].role).toBe("OWNER");
      expect(result.items[1].role).toBe("ADMIN");
    });

    it("should reject when requester is not a member", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(null); // not a member

      await expect(
        service.listMembers(mockUser, "org-1"),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should reject when organization does not exist", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest.spyOn(prisma.organization, "findUnique").mockResolvedValueOnce(null);

      await expect(
        service.listMembers(mockUser, "nonexistent"),
      ).rejects.toThrow(NotFoundException);
    });

    it("should support pagination", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findMany")
        .mockResolvedValueOnce([mockAdminMembership]);
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(50);
      jest
        .spyOn(prisma.user, "findMany")
        .mockResolvedValueOnce([
          { id: mockMember.id, walletAddress: mockMember.walletAddress },
        ]);

      const result = await service.listMembers(mockUser, "org-1", {
        page: 2,
        limit: 25,
      });

      expect(result.page).toBe(2);
      expect(result.limit).toBe(25);
      expect(prisma.organizationMembership.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 25,
          take: 25,
        }),
      );
    });
  });

  describe("updateMemberRole", () => {
    it("should update member role when requester is OWNER", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "update")
        .mockResolvedValueOnce({
          ...mockAdminMembership,
          role: "READER",
        });
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      const result = await service.updateMemberRole(
        mockUser,
        "org-1",
        mockMember.id,
        { role: "READER" },
      );

      expect(result.role).toBe("READER");
      expect(sessionService.revokeAll).toHaveBeenCalledWith(mockMember.id);
    });

    it("should reject updating when requester is not OWNER or ADMIN", async () => {
      const readerMembership = {
        ...mockOwnerMembership,
        userId: mockMember.id,
        role: "READER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(readerMembership); // permission denied

      await expect(
        service.updateMemberRole(mockMember, "org-1", mockUser.id, {
          role: "ADMIN",
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should enforce last-owner protection: prevent demotion of sole owner", async () => {
      const soleOwnerMembership = {
        ...mockAdminMembership,
        role: "OWNER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(soleOwnerMembership); // target is owner
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(1); // only one owner

      await expect(
        service.updateMemberRole(mockUser, "org-1", "some-user", {
          role: "ADMIN",
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should allow demotion when successor owner exists", async () => {
      const targetOwnerMembership = {
        ...mockAdminMembership,
        userId: "user-3",
        role: "OWNER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(targetOwnerMembership); // target is owner
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(2); // multiple owners exist
      jest
        .spyOn(prisma.organizationMembership, "update")
        .mockResolvedValueOnce({
          ...targetOwnerMembership,
          role: "ADMIN",
        });
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest.spyOn(prisma.user, "findUnique").mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      const result = await service.updateMemberRole(
        mockUser,
        "org-1",
        "user-3",
        { role: "ADMIN" },
      );

      expect(result.role).toBe("ADMIN");
    });

    it("should revoke target user sessions on role change", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "update")
        .mockResolvedValueOnce({
          ...mockAdminMembership,
          role: "READER",
        });
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      await service.updateMemberRole(
        mockUser,
        "org-1",
        mockMember.id,
        { role: "READER" },
      );

      expect(sessionService.revokeAll).toHaveBeenCalledWith(mockMember.id);
    });

    it("should create audit log with old and new role", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "update")
        .mockResolvedValueOnce({
          ...mockAdminMembership,
          role: "READER",
        });
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      await service.updateMemberRole(
        mockUser,
        "org-1",
        mockMember.id,
        { role: "READER" },
      );

      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          action: "UPDATE_MEMBER_ROLE",
          metadata: expect.objectContaining({
            oldRole: "ADMIN",
            newRole: "READER",
          }),
        }),
      });
    });
  });

  describe("removeMember", () => {
    it("should remove member when requester is OWNER", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "delete")
        .mockResolvedValueOnce(mockAdminMembership);
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      const result = await service.removeMember(
        mockUser,
        "org-1",
        mockMember.id,
      );

      expect(result.success).toBe(true);
      expect(prisma.organizationMembership.delete).toHaveBeenCalledWith({
        where: {
          organizationId_userId: {
            organizationId: "org-1",
            userId: mockMember.id,
          },
        },
      });
    });

    it("should reject removing when requester is not OWNER or ADMIN", async () => {
      const readerMembership = {
        ...mockOwnerMembership,
        userId: mockMember.id,
        role: "READER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(readerMembership); // permission denied

      await expect(
        service.removeMember(mockMember, "org-1", mockUser.id),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should enforce last-owner protection: prevent removal of sole owner", async () => {
      const soleOwnerMembership = {
        ...mockAdminMembership,
        userId: "owner-user",
        role: "OWNER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(soleOwnerMembership); // target is owner
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(1); // only one owner

      await expect(
        service.removeMember(mockUser, "org-1", "owner-user"),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should allow removal when multiple owners exist", async () => {
      const targetOwnerMembership = {
        ...mockAdminMembership,
        userId: "user-3",
        role: "OWNER" as OrganizationRole,
      };
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(targetOwnerMembership); // target is owner
      jest
        .spyOn(prisma.organizationMembership, "count")
        .mockResolvedValueOnce(2); // multiple owners exist
      jest
        .spyOn(prisma.organizationMembership, "delete")
        .mockResolvedValueOnce(targetOwnerMembership);
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest.spyOn(prisma.user, "findUnique").mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      const result = await service.removeMember(mockUser, "org-1", "user-3");

      expect(result.success).toBe(true);
    });

    it("should revoke removed user sessions", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "delete")
        .mockResolvedValueOnce(mockAdminMembership);
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      await service.removeMember(mockUser, "org-1", mockMember.id);

      expect(sessionService.revokeAll).toHaveBeenCalledWith(mockMember.id);
    });

    it("should create audit log on member removal", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockAdminMembership); // target membership
      jest
        .spyOn(prisma.organizationMembership, "delete")
        .mockResolvedValueOnce(mockAdminMembership);
      jest
        .spyOn(sessionService, "revokeAll")
        .mockResolvedValueOnce(undefined);
      jest
        .spyOn(prisma.user, "findUnique")
        .mockResolvedValueOnce(mockMember);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValueOnce({} as any);

      await service.removeMember(mockUser, "org-1", mockMember.id);

      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          action: "REMOVE_MEMBER",
          metadata: expect.objectContaining({
            targetUserId: mockMember.id,
            role: "ADMIN",
          }),
        }),
      });
    });
  });

  describe("Cross-organization isolation", () => {
    it("should not allow membership from one org to grant access to another org", async () => {
      // Membership in org-1 should not work for org-2
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(null); // no membership in org-2

      await expect(
        service.listMembers(mockUser, "org-2"),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should enforce org context on member lookup", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check for org-1
      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValueOnce(mockOrganization);
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(null); // member NOT found in same org context

      await expect(
        service.updateMemberRole(mockUser, "org-1", "some-user", {
          role: "ADMIN",
        }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("Authorization boundary checks", () => {
    it("should verify org exists before proceeding with invite", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest.spyOn(prisma.organization, "findUnique").mockResolvedValueOnce(null); // org missing

      await expect(
        service.inviteMember(mockUser, "deleted-org", {
          walletAddress: mockMember.walletAddress,
          role: "ADMIN",
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("should verify org exists before proceeding with member removal", async () => {
      jest
        .spyOn(prisma.organizationMembership, "findUnique")
        .mockResolvedValueOnce(mockOwnerMembership); // permission check
      jest.spyOn(prisma.organization, "findUnique").mockResolvedValueOnce(null); // org missing

      await expect(
        service.removeMember(mockUser, "deleted-org", mockMember.id),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
