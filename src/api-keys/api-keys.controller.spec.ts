import { ForbiddenException, BadRequestException } from "@nestjs/common";
import { ApiKeyScope } from "@prisma/client";
import { ApiKeysController } from "./api-keys.controller";
import { AuthenticatedUser } from "../auth/auth.types";

describe("ApiKeysController - Authorization", () => {
  let controller: ApiKeysController;
  let apiKeyService: any;
  let prismaService: any;

  // Mock authenticated users
  const adminUser: AuthenticatedUser = {
    id: "user_admin_123",
    walletAddress: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1",
    walletHash: "hash_admin_123",
    role: "ADMIN",
  };

  const nonAdminUser: AuthenticatedUser = {
    id: "user_nonadmin_456",
    walletAddress: "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB2",
    walletHash: "hash_nonadmin_456",
    role: "WORKER",
  };

  const organizationId = "org_test_789";

  const mockApiKeyService = () => ({
    generateSecret: jest.fn(),
    hashSecret: jest.fn(),
    verifySecret: jest.fn(),
    createKey: jest.fn(),
    rotateKey: jest.fn(),
    revokeKey: jest.fn(),
    listKeysForOrganization: jest.fn(),
    recordKeyUsage: jest.fn(),
  });

  const mockPrismaService = () => ({
    organization: {
      findFirst: jest.fn(),
      create: jest.fn(),
    },
    apiKey: {
      create: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
    },
  });

  beforeEach(() => {
    apiKeyService = mockApiKeyService();
    prismaService = mockPrismaService();
    controller = new ApiKeysController(apiKeyService, prismaService);
  });

  describe("createKey - Authorization", () => {
    it("allows admin user to create API key", async () => {
      // Mock organization lookup - admin user created this org
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      // Mock service response
      apiKeyService.createKey.mockResolvedValueOnce({
        secret: "test_secret_key_123456789",
        apiKey: {
          id: "key_123",
          prefix: "test_se",
          name: "Test Key",
          status: "ACTIVE",
          scopes: [ApiKeyScope.PROOF_VERIFY],
          createdAt: new Date(),
          expiresAt: null,
        },
      });

      const result = await controller.createKey(adminUser, {
        name: "Test Key",
        scopes: [ApiKeyScope.PROOF_VERIFY],
      });

      expect(result.secret).toBeDefined();
      expect(result.apiKey.name).toBe("Test Key");
      expect(apiKeyService.createKey).toHaveBeenCalled();
    });

    it("rejects non-admin user with 403 Forbidden", async () => {
      // Mock organization lookup - non-admin user did NOT create any org
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      const request = controller.createKey(nonAdminUser, {
        name: "Unauthorized Key",
        scopes: [ApiKeyScope.PROOF_VERIFY],
      });

      expect(request).rejects.toThrow(ForbiddenException);
      expect(request).rejects.toThrow(
        /Only organization admins can create API keys/
      );
      // Verify service was NOT called
      expect(apiKeyService.createKey).not.toHaveBeenCalled();
    });

    it("authorization check happens BEFORE service call (fail-closed)", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      try {
        await controller.createKey(nonAdminUser, {
          name: "Test",
          scopes: [ApiKeyScope.PROOF_VERIFY],
        });
      } catch {
        // Expected to throw
      }

      // Verify createKey service was never called
      expect(apiKeyService.createKey).not.toHaveBeenCalled();
    });

    it("validates scopes even for authorized admin", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      const request = controller.createKey(adminUser, {
        name: "Test Key",
        scopes: ["INVALID_SCOPE" as any],
      });

      expect(request).rejects.toThrow(BadRequestException);
      expect(apiKeyService.createKey).not.toHaveBeenCalled();
    });
  });

  describe("listKeys - Authorization", () => {
    it("allows admin user to list API keys", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      apiKeyService.listKeysForOrganization.mockResolvedValueOnce([
        {
          id: "key_1",
          prefix: "prefix1",
          name: "Key 1",
          status: "ACTIVE",
          scopeAssignments: [{ scope: ApiKeyScope.PROOF_VERIFY }],
          createdAt: new Date(),
          rotatedAt: null,
          revokedAt: null,
          expiresAt: null,
          lastUsedAt: null,
        },
      ]);

      const result = await controller.listKeys(adminUser);

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("Key 1");
      expect(apiKeyService.listKeysForOrganization).toHaveBeenCalledWith(
        organizationId
      );
    });

    it("rejects non-admin user with 403 Forbidden", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      const request = controller.listKeys(nonAdminUser);

      expect(request).rejects.toThrow(ForbiddenException);
      expect(request).rejects.toThrow(
        /Only organization admins can list API keys/
      );
      expect(apiKeyService.listKeysForOrganization).not.toHaveBeenCalled();
    });

    it("authorization check happens BEFORE service call (fail-closed)", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      try {
        await controller.listKeys(nonAdminUser);
      } catch {
        // Expected to throw
      }

      expect(apiKeyService.listKeysForOrganization).not.toHaveBeenCalled();
    });
  });

  describe("rotateKey - Authorization", () => {
    it("allows admin user to rotate API key", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      apiKeyService.rotateKey.mockResolvedValueOnce({
        secret: "new_secret_key_987654321",
        apiKey: {
          id: "key_123",
          prefix: "new_se",
          name: "Test Key",
          status: "ACTIVE",
          scopes: [ApiKeyScope.PROOF_VERIFY],
          rotatedAt: new Date(),
        },
      });

      const result = await controller.rotateKey(adminUser, "key_123");

      expect(result.secret).toBeDefined();
      expect(result.apiKey.prefix).toBe("new_se");
      expect(apiKeyService.rotateKey).toHaveBeenCalledWith(
        "key_123",
        organizationId,
        adminUser.id
      );
    });

    it("rejects non-admin user with 403 Forbidden", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      const request = controller.rotateKey(nonAdminUser, "key_123");

      expect(request).rejects.toThrow(ForbiddenException);
      expect(request).rejects.toThrow(
        /Only organization admins can rotate API keys/
      );
      expect(apiKeyService.rotateKey).not.toHaveBeenCalled();
    });

    it("authorization check happens BEFORE service call (fail-closed)", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      try {
        await controller.rotateKey(nonAdminUser, "key_123");
      } catch {
        // Expected to throw
      }

      expect(apiKeyService.rotateKey).not.toHaveBeenCalled();
    });

    it("handles service error when key not found", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      apiKeyService.rotateKey.mockRejectedValueOnce(
        new Error("Key not found")
      );

      await expect(
        controller.rotateKey(adminUser, "key_nonexistent")
      ).rejects.toThrow();

      expect(apiKeyService.rotateKey).toHaveBeenCalled();
    });
  });

  describe("revokeKey - Authorization", () => {
    it("allows admin user to revoke API key", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      apiKeyService.revokeKey.mockResolvedValueOnce(undefined);

      const result = await controller.revokeKey(adminUser, "key_123");

      expect(result.message).toBe("API key revoked successfully");
      expect(apiKeyService.revokeKey).toHaveBeenCalledWith(
        "key_123",
        organizationId,
        adminUser.id
      );
    });

    it("rejects non-admin user with 403 Forbidden", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      const request = controller.revokeKey(nonAdminUser, "key_123");

      expect(request).rejects.toThrow(ForbiddenException);
      expect(request).rejects.toThrow(
        /Only organization admins can revoke API keys/
      );
      expect(apiKeyService.revokeKey).not.toHaveBeenCalled();
    });

    it("authorization check happens BEFORE service call (fail-closed)", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce(null);

      try {
        await controller.revokeKey(nonAdminUser, "key_123");
      } catch {
        // Expected to throw
      }

      expect(apiKeyService.revokeKey).not.toHaveBeenCalled();
    });

    it("handles service error when key not found", async () => {
      prismaService.organization.findFirst.mockResolvedValueOnce({
        id: organizationId,
      });

      apiKeyService.revokeKey.mockRejectedValueOnce(
        new Error("Key not found")
      );

      await expect(
        controller.revokeKey(adminUser, "key_nonexistent")
      ).rejects.toThrow();

      expect(apiKeyService.revokeKey).toHaveBeenCalled();
    });
  });

  describe("Authorization Summary - All Four Endpoints", () => {
    it("admin user can execute all four operations", async () => {
      prismaService.organization.findFirst.mockResolvedValue({
        id: organizationId,
      });

      apiKeyService.createKey.mockResolvedValueOnce({
        secret: "secret_1",
        apiKey: { id: "key_1", prefix: "prefix1", name: "Key 1" },
      });

      apiKeyService.listKeysForOrganization.mockResolvedValueOnce([]);

      apiKeyService.rotateKey.mockResolvedValueOnce({
        secret: "secret_2",
        apiKey: { id: "key_1", prefix: "prefix2", name: "Key 1" },
      });

      apiKeyService.revokeKey.mockResolvedValueOnce(undefined);

      // Create
      const createResult = await controller.createKey(adminUser, {
        name: "Key 1",
      });
      expect(createResult.secret).toBeDefined();

      // List
      const listResult = await controller.listKeys(adminUser);
      expect(listResult).toBeDefined();

      // Rotate
      const rotateResult = await controller.rotateKey(adminUser, "key_1");
      expect(rotateResult.secret).toBeDefined();

      // Revoke
      const revokeResult = await controller.revokeKey(adminUser, "key_1");
      expect(revokeResult.message).toBeDefined();

      // All service methods should have been called exactly once
      expect(apiKeyService.createKey).toHaveBeenCalledTimes(1);
      expect(apiKeyService.listKeysForOrganization).toHaveBeenCalledTimes(1);
      expect(apiKeyService.rotateKey).toHaveBeenCalledTimes(1);
      expect(apiKeyService.revokeKey).toHaveBeenCalledTimes(1);
    });

    it("non-admin user is rejected from all four operations", async () => {
      prismaService.organization.findFirst.mockResolvedValue(null);

      // Create should fail
      expect(
        controller.createKey(nonAdminUser, { name: "Key" })
      ).rejects.toThrow(ForbiddenException);

      // List should fail
      expect(controller.listKeys(nonAdminUser)).rejects.toThrow(
        ForbiddenException
      );

      // Rotate should fail
      expect(controller.rotateKey(nonAdminUser, "key_1")).rejects.toThrow(
        ForbiddenException
      );

      // Revoke should fail
      expect(controller.revokeKey(nonAdminUser, "key_1")).rejects.toThrow(
        ForbiddenException
      );

      // No service methods should have been called
      expect(apiKeyService.createKey).not.toHaveBeenCalled();
      expect(apiKeyService.listKeysForOrganization).not.toHaveBeenCalled();
      expect(apiKeyService.rotateKey).not.toHaveBeenCalled();
      expect(apiKeyService.revokeKey).not.toHaveBeenCalled();
    });
  });
});
