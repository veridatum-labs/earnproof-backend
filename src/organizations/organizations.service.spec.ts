import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { Test, TestingModule } from "@nestjs/testing";
import { PrismaService } from "../database/prisma.service";
import { OrganizationsService } from "./organizations.service";

describe("OrganizationsService", () => {
  let service: OrganizationsService;
  let prisma: PrismaService;

  const mockUser = {
    id: "user-1",
    walletAddress: "G1111111111111111111111111111111111111111111111111111111",
    walletHash: "sha256:hash1",
    role: "ADMIN",
  };

  const mockIssuerUser = {
    id: "issuer-1",
    walletAddress: "G2222222222222222222222222222222222222222222222222222222",
    walletHash: "sha256:hash2",
    role: "ISSUER",
  };

  const mockOrganization = {
    id: "org-1",
    name: "Test Organization",
    slug: "test-org",
    website: "https://example.com",
    status: ResourceStatus.PENDING,
    revision: 1,
    createdById: mockUser.id,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrganizationsService,
        {
          provide: PrismaService,
          useValue: {
            organization: {
              create: jest.fn(),
              update: jest.fn(),
              updateMany: jest.fn(),
              findFirst: jest.fn(),
              findUnique: jest.fn(),
              findMany: jest.fn(),
              count: jest.fn(),
            },
            issuer: {
              count: jest.fn(),
            },
            auditLog: {
              create: jest.fn(),
            },
            $transaction: jest.fn((callback) => callback({
              organization: {
                updateMany: jest.fn(),
                findUnique: jest.fn(),
              },
            })),
          },
        },
      ],
    }).compile();

    service = module.get<OrganizationsService>(OrganizationsService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  describe("createOrganization", () => {
    it("should create organization when user is admin", async () => {
      const input = {
        name: "Test Organization",
        slug: "test-org",
        website: "https://example.com",
      };

      jest.spyOn(prisma.organization, "findUnique").mockResolvedValue(null);
      jest
        .spyOn(prisma.organization, "create")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.createOrganization(mockUser, input);

      expect(result.id).toBe(mockOrganization.id);
      expect(result.name).toBe(input.name);
      expect(result.status).toBe(ResourceStatus.PENDING);
      expect(result.revision).toBe(1);
      expect(prisma.organization.create).toHaveBeenCalledWith({
        data: {
          name: input.name,
          slug: input.slug,
          website: input.website,
          createdById: mockUser.id,
          status: ResourceStatus.PENDING,
        },
      });
    });

    it("should reject when user is not admin", async () => {
      const input = {
        name: "Test Organization",
        slug: "test-org",
        website: "https://example.com",
      };

      await expect(
        service.createOrganization(mockIssuerUser, input),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should reject duplicate slug", async () => {
      const input = {
        name: "Test Organization",
        slug: "test-org",
        website: "https://example.com",
      };

      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValue(mockOrganization);

      await expect(service.createOrganization(mockUser, input)).rejects.toThrow(
        ConflictException,
      );
    });

    it("should create audit log on success", async () => {
      const input = {
        name: "Test Organization",
        slug: "test-org",
        website: "https://example.com",
      };

      jest.spyOn(prisma.organization, "findUnique").mockResolvedValue(null);
      jest
        .spyOn(prisma.organization, "create")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      await service.createOrganization(mockUser, input);

      expect(prisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          actorId: mockUser.id,
          action: "CREATE",
          resourceType: "Organization",
          resourceId: mockOrganization.id,
        }),
      });
    });
  });

  describe("updateOrganization - revision checking", () => {
    it("should reject update when revision is stale", async () => {
      const input = {
        revision: 1,
        name: "Updated Name",
      };

      const orgWithLatestRevision = {
        ...mockOrganization,
        revision: 2,
      };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(orgWithLatestRevision);

      await expect(
        service.updateOrganization(mockUser, "org-1", input),
      ).rejects.toThrow(ConflictException);
    });

    it("should include current revision in conflict response", async () => {
      const input = {
        revision: 1,
        name: "Updated Name",
      };

      const orgWithLatestRevision = {
        ...mockOrganization,
        revision: 2,
      };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(orgWithLatestRevision);

      try {
        await service.updateOrganization(mockUser, "org-1", input);
        fail("Should have thrown ConflictException");
      } catch (e) {
        expect(e).toBeInstanceOf(ConflictException);
        const errorMessage = (e as ConflictException).getResponse() as any;
        expect(errorMessage).toContain("2"); // current revision
      }
    });

    it("should atomically update and increment revision", async () => {
      const input = {
        revision: 1,
        name: "Updated Name",
      };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(mockOrganization);

      const mockTx = {
        organization: {
          updateMany: jest.fn().mockResolvedValue({ count: 1 }),
          findUnique: jest
            .fn()
            .mockResolvedValue({
              ...mockOrganization,
              name: "Updated Name",
              revision: 2,
            }),
        },
      };

      jest.spyOn(prisma, "$transaction").mockImplementation((fn: any) => {
        return fn(mockTx);
      });

      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.updateOrganization(mockUser, "org-1", input);

      expect(result.name).toBe("Updated Name");
      expect(result.revision).toBe(2);
      expect(mockTx.organization.updateMany).toHaveBeenCalledWith({
        where: {
          id: "org-1",
          revision: 1, // Double-check
        },
        data: {
          name: "Updated Name",
          revision: 2, // Incremented
        },
      });
    });

    it("should fail update if concurrent write detected", async () => {
      const input = {
        revision: 1,
        name: "Updated Name",
      };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(mockOrganization);

      const mockTx = {
        organization: {
          updateMany: jest.fn().mockResolvedValue({ count: 0 }), // No rows matched
          findUnique: jest
            .fn()
            .mockResolvedValue({
              ...mockOrganization,
              revision: 2,
            }),
        },
      };

      jest.spyOn(prisma, "$transaction").mockImplementation((fn: any) => {
        return fn(mockTx);
      });

      await expect(
        service.updateOrganization(mockUser, "org-1", input),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe("updateOrganization", () => {
    it("should update organization when user is creator", async () => {
      const input = { name: "Updated Name" };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(mockOrganization);
      jest
        .spyOn(prisma.organization, "update")
        .mockResolvedValue({ ...mockOrganization, name: input.name });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.updateOrganization(mockUser, "org-1", input);

      expect(result.name).toBe(input.name);
      expect(prisma.organization.update).toHaveBeenCalledWith({
        where: { id: "org-1" },
        data: { name: input.name },
      });
    });

    it("should reject when user is not creator and not admin", async () => {
      const input = { name: "Updated Name" };

      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(null);

      await expect(
        service.updateOrganization(mockIssuerUser, "org-1", input),
      ).rejects.toThrow(NotFoundException);
    });

    it("should not fail when org not found - handled by getOrganizationById", async () => {
      const input = { name: "Updated Name" };

      jest.spyOn(prisma.organization, "findFirst").mockResolvedValue(null);

      await expect(
        service.updateOrganization(mockUser, "nonexistent", input),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("listOrganizations", () => {
    it("should list organizations for admin", async () => {
      jest
        .spyOn(prisma.organization, "findMany")
        .mockResolvedValue([mockOrganization]);
      jest.spyOn(prisma.organization, "count").mockResolvedValue(1);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(0);

      const result = await service.listOrganizations(mockUser, {});

      expect(result.items).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(20);
    });

    it("should filter organizations by status", async () => {
      jest
        .spyOn(prisma.organization, "findMany")
        .mockResolvedValue([mockOrganization]);
      jest.spyOn(prisma.organization, "count").mockResolvedValue(1);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(0);

      const result = await service.listOrganizations(mockUser, {
        status: ResourceStatus.PENDING,
      });

      expect(result.items).toHaveLength(1);
      expect(prisma.organization.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: ResourceStatus.PENDING,
          }),
        }),
      );
    });

    it("should restrict non-admin users to their own organizations and memberships", async () => {
      jest
        .spyOn(prisma.organization, "findMany")
        .mockResolvedValue([mockOrganization]);
      jest.spyOn(prisma.organization, "count").mockResolvedValue(1);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(0);

      await service.listOrganizations(mockIssuerUser, {});

      expect(prisma.organization.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            OR: expect.arrayContaining([
              { createdById: mockIssuerUser.id },
              expect.objectContaining({
                memberships: {
                  some: {
                    userId: mockIssuerUser.id,
                  },
                },
              }),
            ]),
          }),
        }),
      );
    });

    it("should paginate results", async () => {
      jest
        .spyOn(prisma.organization, "findMany")
        .mockResolvedValue([mockOrganization]);
      jest.spyOn(prisma.organization, "count").mockResolvedValue(50);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(0);

      const result = await service.listOrganizations(mockUser, {
        page: 2,
        limit: 20,
      });

      expect(result.page).toBe(2);
      expect(result.limit).toBe(20);
      expect(prisma.organization.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 20,
          take: 20,
        }),
      );
    });
  });

  describe("getOrganization", () => {
    it("should return organization with issuer count", async () => {
      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(3);

      const result = await service.getOrganization(mockUser, "org-1");

      expect(result.id).toBe(mockOrganization.id);
      expect(result.issuerCount).toBe(3);
    });

    it("should throw when organization not found", async () => {
      jest.spyOn(prisma.organization, "findFirst").mockResolvedValue(null);

      await expect(
        service.getOrganization(mockUser, "nonexistent"),
      ).rejects.toThrow(NotFoundException);
    });

    it("should reject access to another user's organization", async () => {
      jest
        .spyOn(prisma.organization, "findFirst")
        .mockResolvedValue(null);

      await expect(
        service.getOrganization(mockIssuerUser, "org-1"),
      ).rejects.toThrow(NotFoundException);
      expect(prisma.issuer.count).not.toHaveBeenCalled();
    });
  });
});
