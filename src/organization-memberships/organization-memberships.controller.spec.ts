import { Test, TestingModule } from "@nestjs/testing";
import { AuthGuard } from "../common/guards/auth.guard";
import { OrganizationRole } from "@prisma/client";
import { OrganizationMembershipsController } from "./organization-memberships.controller";
import { OrganizationMembershipsService } from "./organization-memberships.service";

describe("OrganizationMembershipsController", () => {
  let controller: OrganizationMembershipsController;
  let service: OrganizationMembershipsService;

  const mockUser = {
    id: "user-1",
    walletAddress: "GOWNER1111111111111111111111111111111111111111111111111",
    walletHash: "hash1",
    role: "ADMIN",
    sessionId: "session-1",
  };

  const mockMemberResponse = {
    id: "membership-1",
    organizationId: "org-1",
    userId: "user-2",
    walletAddress: "GMEMBER11111111111111111111111111111111111111111111111",
    role: "ADMIN" as OrganizationRole,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [OrganizationMembershipsController],
      providers: [
        {
          provide: OrganizationMembershipsService,
          useValue: {
            inviteMember: jest.fn(),
            listMembers: jest.fn(),
            updateMemberRole: jest.fn(),
            removeMember: jest.fn(),
          },
        },
      ],
    })
      .overrideGuard(AuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<OrganizationMembershipsController>(
      OrganizationMembershipsController,
    );
    service = module.get<OrganizationMembershipsService>(
      OrganizationMembershipsService,
    );
  });

  describe("POST /organizations/:organizationId/members", () => {
    it("should call inviteMember with correct parameters", async () => {
      const input = {
        walletAddress: mockMemberResponse.walletAddress,
        role: "ADMIN" as OrganizationRole,
      };

      jest.spyOn(service, "inviteMember").mockResolvedValueOnce(mockMemberResponse);

      const result = await controller.inviteMember(
        mockUser,
        "org-1",
        input,
      );

      expect(result).toEqual(mockMemberResponse);
      expect(service.inviteMember).toHaveBeenCalledWith(mockUser, "org-1", input);
    });
  });

  describe("GET /organizations/:organizationId/members", () => {
    it("should call listMembers with organization id", async () => {
      const listResult = {
        items: [mockMemberResponse],
        total: 1,
        page: 1,
        limit: 20,
      };

      jest.spyOn(service, "listMembers").mockResolvedValueOnce(listResult);

      const result = await controller.listMembers(mockUser, "org-1");

      expect(result).toEqual(listResult);
      expect(service.listMembers).toHaveBeenCalledWith(
        mockUser,
        "org-1",
        { page: undefined, limit: undefined },
      );
    });

    it("should pass pagination parameters", async () => {
      const listResult = {
        items: [mockMemberResponse],
        total: 1,
        page: 2,
        limit: 25,
      };

      jest.spyOn(service, "listMembers").mockResolvedValueOnce(listResult);

      await controller.listMembers(mockUser, "org-1", 2, 25);

      expect(service.listMembers).toHaveBeenCalledWith(
        mockUser,
        "org-1",
        { page: 2, limit: 25 },
      );
    });
  });

  describe("PATCH /organizations/:organizationId/members/:userId", () => {
    it("should call updateMemberRole with correct parameters", async () => {
      const input = { role: "READER" as OrganizationRole };
      const updatedMember = { ...mockMemberResponse, role: "READER" as OrganizationRole };

      jest.spyOn(service, "updateMemberRole").mockResolvedValueOnce(updatedMember);

      const result = await controller.updateMemberRole(
        mockUser,
        "org-1",
        "user-2",
        input,
      );

      expect(result).toEqual(updatedMember);
      expect(service.updateMemberRole).toHaveBeenCalledWith(
        mockUser,
        "org-1",
        "user-2",
        input,
      );
    });
  });

  describe("DELETE /organizations/:organizationId/members/:userId", () => {
    it("should call removeMember and return success", async () => {
      jest.spyOn(service, "removeMember").mockResolvedValueOnce({ success: true });

      const result = await controller.removeMember(mockUser, "org-1", "user-2");

      expect(result).toEqual({ success: true });
      expect(service.removeMember).toHaveBeenCalledWith(mockUser, "org-1", "user-2");
    });
  });
});
