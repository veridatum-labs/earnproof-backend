import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { Test, TestingModule } from "@nestjs/testing";
import { ContractAnchoringService } from "../proofs/contract-anchoring.service";
import { PrismaService } from "../database/prisma.service";
import { IssuersService } from "./issuers.service";

describe("IssuersService", () => {
  let service: IssuersService;
  let prisma: PrismaService;
  let contractAnchoring: ContractAnchoringService;

  const mockUser = {
    id: "user-1",
    walletAddress: "G1111111111111111111111111111111111111111111111111111111",
    walletHash: "sha256:hash1",
    role: "ADMIN",
  };

  const mockNonAdminUser = {
    id: "user-2",
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
    createdById: mockUser.id,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  const mockIssuer = {
    id: "issuer-1",
    organizationId: "org-1",
    stellarAddress: "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
    status: ResourceStatus.PENDING,
    metadataHash: "hash123",
    verifiedAt: null,
    suspendedAt: null,
    revokedAt: null,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IssuersService,
        {
          provide: PrismaService,
          useValue: {
            organization: {
              findUnique: jest.fn(),
            },
            issuer: {
              create: jest.fn(),
              update: jest.fn(),
              findUnique: jest.fn(),
              findMany: jest.fn(),
              count: jest.fn(),
            },
            auditLog: {
              create: jest.fn(),
            },
          },
        },
        {
          provide: ContractAnchoringService,
          useValue: {
            anchorProof: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<IssuersService>(IssuersService);
    prisma = module.get<PrismaService>(PrismaService);
    contractAnchoring =
      module.get<ContractAnchoringService>(ContractAnchoringService);
  });

  describe("createIssuer", () => {
    it("should create issuer when admin", async () => {
      const input = {
        organizationId: "org-1",
        stellarAddress:
          "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
        publicMetadata: { name: "Test Issuer" },
      };

      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.issuer, "findUnique").mockResolvedValue(null);
      jest.spyOn(prisma.issuer, "create").mockResolvedValue(mockIssuer);
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.createIssuer(mockUser, input);

      expect(result.id).toBe(mockIssuer.id);
      expect(result.status).toBe(ResourceStatus.PENDING);
      expect(prisma.issuer.create).toHaveBeenCalled();
    });

    it("should reject when user is not admin", async () => {
      const input = {
        organizationId: "org-1",
        stellarAddress:
          "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
      };

      await expect(
        service.createIssuer(mockNonAdminUser, input),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should reject duplicate stellar address", async () => {
      const input = {
        organizationId: "org-1",
        stellarAddress:
          "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
      };

      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.issuer, "findUnique").mockResolvedValue(mockIssuer);

      await expect(service.createIssuer(mockUser, input)).rejects.toThrow(
        ConflictException,
      );
    });

    it("should reject invalid stellar address format", async () => {
      const input = {
        organizationId: "org-1",
        stellarAddress: "INVALID_ADDRESS",
      };

      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValue(mockOrganization);
      jest.spyOn(prisma.issuer, "findUnique").mockResolvedValue(null);

      await expect(service.createIssuer(mockUser, input)).rejects.toThrow(
        BadRequestException,
      );
    });

    it("should reject when organization not found", async () => {
      const input = {
        organizationId: "nonexistent",
        stellarAddress:
          "GBUQWP3BOUZX34ULNQG23RQ6F4BVWCIBTBTQUGS7SEEDS23ABC123DEF45",
      };

      jest
        .spyOn(prisma.organization, "findUnique")
        .mockResolvedValue(null);

      await expect(service.createIssuer(mockUser, input)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe("updateIssuerStatus", () => {
    it("should transition from PENDING to ACTIVE", async () => {
      const input = { status: ResourceStatus.ACTIVE };

      jest.spyOn(prisma.issuer, "findUnique").mockResolvedValue(mockIssuer);
      jest.spyOn(prisma.issuer, "update").mockResolvedValue({
        ...mockIssuer,
        status: ResourceStatus.ACTIVE,
        verifiedAt: new Date(),
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.updateIssuerStatus(
        mockUser,
        "issuer-1",
        input,
      );

      expect(result.status).toBe(ResourceStatus.ACTIVE);
      expect(prisma.issuer.update).toHaveBeenCalled();
    });

    it("should reject invalid status transition", async () => {
      const input = { status: ResourceStatus.PENDING };
      const activeIssuer = { ...mockIssuer, status: ResourceStatus.ACTIVE };

      jest
        .spyOn(prisma.issuer, "findUnique")
        .mockResolvedValue(activeIssuer);

      await expect(
        service.updateIssuerStatus(mockUser, "issuer-1", input),
      ).rejects.toThrow(BadRequestException);
    });

    it("should reject when user is not admin", async () => {
      const input = { status: ResourceStatus.ACTIVE };

      await expect(
        service.updateIssuerStatus(mockNonAdminUser, "issuer-1", input),
      ).rejects.toThrow(ForbiddenException);
    });

    it("should set verifiedAt when transitioning to ACTIVE", async () => {
      const input = { status: ResourceStatus.ACTIVE };

      jest.spyOn(prisma.issuer, "findUnique").mockResolvedValue(mockIssuer);
      jest.spyOn(prisma.issuer, "update").mockResolvedValue({
        ...mockIssuer,
        status: ResourceStatus.ACTIVE,
        verifiedAt: new Date(),
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      await service.updateIssuerStatus(mockUser, "issuer-1", input);

      expect(prisma.issuer.update).toHaveBeenCalledWith({
        where: { id: "issuer-1" },
        data: expect.objectContaining({
          status: ResourceStatus.ACTIVE,
          verifiedAt: expect.any(Date),
        }),
      });
    });

    it("should set suspendedAt when transitioning to SUSPENDED", async () => {
      const input = { status: ResourceStatus.SUSPENDED };
      const activeIssuer = { ...mockIssuer, status: ResourceStatus.ACTIVE };

      jest
        .spyOn(prisma.issuer, "findUnique")
        .mockResolvedValue(activeIssuer);
      jest.spyOn(prisma.issuer, "update").mockResolvedValue({
        ...activeIssuer,
        status: ResourceStatus.SUSPENDED,
        suspendedAt: new Date(),
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      await service.updateIssuerStatus(mockUser, "issuer-1", input);

      expect(prisma.issuer.update).toHaveBeenCalledWith({
        where: { id: "issuer-1" },
        data: expect.objectContaining({
          status: ResourceStatus.SUSPENDED,
          suspendedAt: expect.any(Date),
        }),
      });
    });

    it("should set revokedAt when transitioning to REVOKED", async () => {
      const input = { status: ResourceStatus.REVOKED };
      const activeIssuer = { ...mockIssuer, status: ResourceStatus.ACTIVE };

      jest
        .spyOn(prisma.issuer, "findUnique")
        .mockResolvedValue(activeIssuer);
      jest.spyOn(prisma.issuer, "update").mockResolvedValue({
        ...activeIssuer,
        status: ResourceStatus.REVOKED,
        revokedAt: new Date(),
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      await service.updateIssuerStatus(mockUser, "issuer-1", input);

      expect(prisma.issuer.update).toHaveBeenCalledWith({
        where: { id: "issuer-1" },
        data: expect.objectContaining({
          status: ResourceStatus.REVOKED,
          revokedAt: expect.any(Date),
        }),
      });
    });
  });

  describe("syncIssuerStatus", () => {
    it("should sync issuer status to contract", async () => {
      const activeIssuer = {
        ...mockIssuer,
        status: ResourceStatus.ACTIVE,
        verifiedAt: new Date(),
      };

      jest
        .spyOn(prisma.issuer, "findUnique")
        .mockResolvedValue(activeIssuer);
      jest.spyOn(contractAnchoring, "anchorProof").mockResolvedValue({
        anchored: true,
        transactionHash: "tx123",
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.syncIssuerStatus(mockUser, "issuer-1");

      expect(result.synced).toBe(true);
      expect(result.transactionHash).toBe("tx123");
      expect(contractAnchoring.anchorProof).toHaveBeenCalled();
    });

    it("should handle sync failure gracefully", async () => {
      jest
        .spyOn(prisma.issuer, "findUnique")
        .mockResolvedValue(mockIssuer);
      jest.spyOn(contractAnchoring, "anchorProof").mockResolvedValue({
        anchored: false,
        reason: "failed",
        error: "Network error",
      });
      jest.spyOn(prisma.auditLog, "create").mockResolvedValue({} as any);

      const result = await service.syncIssuerStatus(mockUser, "issuer-1");

      expect(result.synced).toBe(false);
      expect(result.reason).toBe("failed");
      expect(result.error).toBe("Network error");
    });

    it("should reject when user is not admin", async () => {
      await expect(
        service.syncIssuerStatus(mockNonAdminUser, "issuer-1"),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  describe("listIssuersPublic", () => {
    it("should list only active/pending issuers", async () => {
      jest
        .spyOn(prisma.issuer, "findMany")
        .mockResolvedValue([mockIssuer]);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(1);

      const result = await service.listIssuersPublic({});

      expect(result.items).toHaveLength(1);
      expect(prisma.issuer.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: {
              in: [ResourceStatus.ACTIVE, ResourceStatus.PENDING],
            },
          }),
        }),
      );
    });

    it("should filter by organization", async () => {
      jest
        .spyOn(prisma.issuer, "findMany")
        .mockResolvedValue([mockIssuer]);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(1);

      await service.listIssuersPublic({
        organizationId: "org-1",
      });

      expect(prisma.issuer.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            organizationId: "org-1",
          }),
        }),
      );
    });

    it("should compute trust status correctly", async () => {
      const trustedIssuer = {
        ...mockIssuer,
        status: ResourceStatus.ACTIVE,
        verifiedAt: new Date(),
      };

      jest
        .spyOn(prisma.issuer, "findMany")
        .mockResolvedValue([trustedIssuer]);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(1);

      const result = await service.listIssuersPublic({});

      expect(result.items[0].trustStatus).toBe("TRUSTED");
    });

    it("should paginate results", async () => {
      jest
        .spyOn(prisma.issuer, "findMany")
        .mockResolvedValue([mockIssuer]);
      jest.spyOn(prisma.issuer, "count").mockResolvedValue(50);

      const result = await service.listIssuersPublic({
        page: 2,
        limit: 10,
      });

      expect(result.page).toBe(2);
      expect(result.limit).toBe(10);
      expect(prisma.issuer.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          skip: 10,
          take: 10,
        }),
      );
    });
  });

  describe("computeTrustStatus", () => {
    it("should return REVOKED when revokedAt is set", () => {
      const issuer = { ...mockIssuer, revokedAt: new Date() };
      // Access private method via service instance for testing
      const result = (service as any).computeTrustStatus(issuer);
      expect(result).toBe("REVOKED");
    });

    it("should return SUSPENDED when suspendedAt is set", () => {
      const issuer = { ...mockIssuer, suspendedAt: new Date() };
      const result = (service as any).computeTrustStatus(issuer);
      expect(result).toBe("SUSPENDED");
    });

    it("should return TRUSTED when verifiedAt is set", () => {
      const issuer = { ...mockIssuer, verifiedAt: new Date() };
      const result = (service as any).computeTrustStatus(issuer);
      expect(result).toBe("TRUSTED");
    });

    it("should return PENDING when no timestamps are set", () => {
      const result = (service as any).computeTrustStatus(mockIssuer);
      expect(result).toBe("PENDING");
    });
  });
});
