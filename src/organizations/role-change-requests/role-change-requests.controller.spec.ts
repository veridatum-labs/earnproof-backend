import { Test, TestingModule } from "@nestjs/testing";
import { Request } from "express";
import { AuthenticatedUser } from "../../auth/auth.types";
import { AuthTokenService } from "../../auth/auth-token.service";
import { AuthGuard } from "../../common/guards/auth.guard";
import { RoleGuard } from "../../common/guards/role.guard";
import { RoleChangeRequestsController } from "./role-change-requests.controller";
import { RoleChangeRequestsService } from "./role-change-requests.service";
import { CreateRoleChangeRequestDto } from "./dto/create-role-change-request.dto";
import { ApproveRoleChangeRequestDto } from "./dto/approve-role-change-request.dto";
import { RejectRoleChangeRequestDto } from "./dto/reject-role-change-request.dto";
import { CancelRoleChangeRequestDto } from "./dto/cancel-role-change-request.dto";
import { ListRoleChangeRequestsDto } from "./dto/list-role-change-requests.dto";
import { RoleChangeRequestResponseDto } from "./dto/role-change-request-response.dto";

describe("RoleChangeRequestsController", () => {
  let controller: RoleChangeRequestsController;
  let service: RoleChangeRequestsService;

  const mockUser: AuthenticatedUser = {
    id: "user-approver",
    walletAddress: "G1111111111111111111111111111111111111111111111111111111",
    walletHash: "sha256:approver",
    role: "ADMIN",
  };

  const mockOrgId = "org-1";
  const mockRequestId = "req-1";

  const mockResponseDto: RoleChangeRequestResponseDto = {
    id: mockRequestId,
    organizationId: mockOrgId,
    targetMemberId: "target-member-id",
    targetUserId: "target-user-id",
    requesterMemberId: "requester-member-id",
    requesterUserId: "user-requester",
    currentRole: "MEMBER",
    proposedRole: "ADMIN",
    expectedMemberRevision: 0,
    status: "PENDING",
    justification: "Promotion to team lead requiring admin permissions",
    requiredApprovals: 1,
    currentApprovals: 0,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    decidedAt: null,
    decisionReason: null,
    appliedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    approvals: [],
    targetMember: {
      id: "target-member-id",
      userId: "target-user-id",
      role: "MEMBER",
      revision: 0,
    },
    requester: {
      id: "user-requester",
      walletAddress: "G2222222222222222222222222222222222222222222222222222222",
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RoleChangeRequestsController],
      providers: [
        {
          provide: RoleChangeRequestsService,
          useValue: {
            create: jest.fn(),
            list: jest.fn(),
            get: jest.fn(),
            approve: jest.fn(),
            reject: jest.fn(),
            cancel: jest.fn(),
          },
        },
        {
          provide: AuthTokenService,
          useValue: {
            verify: jest.fn(),
          },
        },
      ],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: jest.fn(() => true) })
      .overrideGuard(RoleGuard)
      .useValue({ canActivate: jest.fn(() => true) })
      .compile();

    controller = module.get<RoleChangeRequestsController>(RoleChangeRequestsController);
    service = module.get<RoleChangeRequestsService>(RoleChangeRequestsService);
  });

  describe("create", () => {
    it("delegates to service.create with user, organizationId, and dto", async () => {
      const dto: CreateRoleChangeRequestDto = {
        targetMemberId: "target-member-id",
        proposedRole: "ADMIN",
        justification: "Promotion to team lead requiring admin permissions",
        expectedMemberRevision: 0,
      };

      jest.spyOn(service, "create").mockResolvedValue(mockResponseDto);

      const result = await controller.create(mockUser, mockOrgId, dto);

      expect(result).toEqual(mockResponseDto);
      expect(service.create).toHaveBeenCalledWith(mockUser, mockOrgId, dto);
    });
  });

  describe("list", () => {
    it("delegates to service.list with user, organizationId, and query params", async () => {
      const query: ListRoleChangeRequestsDto = {
        status: "PENDING",
        page: 1,
        limit: 10,
      };

      const paginatedResult = {
        data: [mockResponseDto],
        meta: { page: 1, limit: 10, total: 1, totalPages: 1 },
      };

      jest.spyOn(service, "list").mockResolvedValue(paginatedResult);

      const result = await controller.list(mockUser, mockOrgId, query);

      expect(result).toEqual(paginatedResult);
      expect(service.list).toHaveBeenCalledWith(mockUser, mockOrgId, query);
    });
  });

  describe("get", () => {
    it("delegates to service.get with user, organizationId, and requestId", async () => {
      jest.spyOn(service, "get").mockResolvedValue(mockResponseDto);

      const result = await controller.get(mockUser, mockOrgId, mockRequestId);

      expect(result).toEqual(mockResponseDto);
      expect(service.get).toHaveBeenCalledWith(mockUser, mockOrgId, mockRequestId);
    });
  });

  describe("approve", () => {
    it("extracts x-recent-auth and origin headers and delegates to service.approve", async () => {
      const dto: ApproveRoleChangeRequestDto = {
        notes: "Approved after security review",
      };

      const mockReq = {
        headers: {
          "x-recent-auth": "assertion-token-123",
          origin: "https://app.earnproof.com",
        },
      } as unknown as Request;

      const approvedResponse = {
        ...mockResponseDto,
        status: "APPROVED" as const,
        decidedAt: new Date().toISOString(),
        appliedAt: new Date().toISOString(),
      };

      jest.spyOn(service, "approve").mockResolvedValue(approvedResponse);

      const result = await controller.approve(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
        mockReq,
      );

      expect(result).toEqual(approvedResponse);
      expect(service.approve).toHaveBeenCalledWith(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
        "assertion-token-123",
        "https://app.earnproof.com",
      );
    });

    it("handles missing headers gracefully by passing empty string and null origin", async () => {
      const dto: ApproveRoleChangeRequestDto = {};
      const mockReq = {
        headers: {},
      } as unknown as Request;

      jest.spyOn(service, "approve").mockResolvedValue(mockResponseDto);

      await controller.approve(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
        mockReq,
      );

      expect(service.approve).toHaveBeenCalledWith(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
        "",
        "null",
      );
    });
  });

  describe("reject", () => {
    it("delegates to service.reject with user, organizationId, requestId, and dto", async () => {
      const dto: RejectRoleChangeRequestDto = {
        reason: "Does not meet security prerequisites",
      };

      const rejectedResponse = {
        ...mockResponseDto,
        status: "REJECTED" as const,
        decidedAt: new Date().toISOString(),
        decisionReason: dto.reason,
      };

      jest.spyOn(service, "reject").mockResolvedValue(rejectedResponse);

      const result = await controller.reject(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
      );

      expect(result).toEqual(rejectedResponse);
      expect(service.reject).toHaveBeenCalledWith(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
      );
    });
  });

  describe("cancel", () => {
    it("delegates to service.cancel with user, organizationId, requestId, and dto", async () => {
      const dto: CancelRoleChangeRequestDto = {
        reason: "Request submitted by mistake",
      };

      const cancelledResponse = {
        ...mockResponseDto,
        status: "CANCELLED" as const,
        decidedAt: new Date().toISOString(),
        decisionReason: dto.reason,
      };

      jest.spyOn(service, "cancel").mockResolvedValue(cancelledResponse);

      const result = await controller.cancel(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
      );

      expect(result).toEqual(cancelledResponse);
      expect(service.cancel).toHaveBeenCalledWith(
        mockUser,
        mockOrgId,
        mockRequestId,
        dto,
      );
    });
  });
});
