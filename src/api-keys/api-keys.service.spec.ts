import { ForbiddenException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { sha256 } from "../common/crypto/hash";
import { ApiKeysService } from "./api-keys.service";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPrisma(overrides: Record<string, unknown> = {}) {
  return {
    apiKey: {
      create: jest.fn(),
      findMany: jest.fn().mockResolvedValue([]),
      findUnique: jest.fn().mockResolvedValue(null),
      findFirst: jest.fn().mockResolvedValue(null),
      update: jest.fn(),
    },
    organization: {
      findUnique: jest.fn().mockResolvedValue({
        id: "org_1",
        status: ResourceStatus.ACTIVE,
      }),
    },
    auditLog: {
      create: jest.fn().mockResolvedValue({ id: "audit_1" }),
    },
    ...overrides,
  };
}

const adminActor = { id: "user_1", role: "ADMIN" };
const workerActor = { id: "user_2", role: "WORKER" };
const ORG_ID = "org_1";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ApiKeysService", () => {
  // -------------------------------------------------------------------------
  // createApiKey
  // -------------------------------------------------------------------------
  describe("createApiKey", () => {
    it("returns a one-time secret with the key metadata", async () => {
      const prisma = buildPrisma();
      const created = {
        id: "key_1",
        name: "CI key",
        keyPrefix: expect.stringMatching(/^ep_[a-f0-9]{12}_$/),
        scopes: ["proofs:read"],
        status: ResourceStatus.ACTIVE,
        expiresAt: null,
        createdAt: new Date(),
      };
      (prisma.apiKey.create as jest.Mock).mockResolvedValue(created);

      const service = new ApiKeysService(prisma as never);

      const result = await service.createApiKey(adminActor, ORG_ID, {
        name: "CI key",
        scopes: ["proofs:read"],
      });

      expect(result.secret).toMatch(/^ep_[a-f0-9]{12}_[a-f0-9]{64}$/);
      expect(result.id).toBe("key_1");
      // Secret must not leak into the persisted hash
      expect(result).not.toHaveProperty("keyHash");
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: "api_key.created",
            actorId: "user_1",
          }),
        }),
      );
    });

    it("stores the sha256 hash, never the raw secret", async () => {
      let storedHash: string | undefined;
      const prisma = buildPrisma();
      (prisma.apiKey.create as jest.Mock).mockImplementation(
        async ({ data }: { data: { keyHash: string } }) => {
          storedHash = data.keyHash;
          return { id: "key_1", name: "key", keyPrefix: "ep_aaa_", scopes: [], status: ResourceStatus.ACTIVE, expiresAt: null, createdAt: new Date() };
        },
      );

      const service = new ApiKeysService(prisma as never);
      const result = await service.createApiKey(adminActor, ORG_ID, {
        name: "key",
        scopes: ["proofs:read"],
      });

      expect(storedHash).toBe(`sha256:${sha256(result.secret)}`);
      expect(storedHash).not.toContain(result.secret);
    });

    it("rejects WORKER role with ForbiddenException", async () => {
      const prisma = buildPrisma();
      const service = new ApiKeysService(prisma as never);

      await expect(
        service.createApiKey(workerActor, ORG_ID, {
          name: "key",
          scopes: ["proofs:read"],
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it("rejects when organization does not exist", async () => {
      const prisma = buildPrisma();
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue(null);
      const service = new ApiKeysService(prisma as never);

      await expect(
        service.createApiKey(adminActor, "missing_org", {
          name: "key",
          scopes: ["proofs:read"],
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("rejects when organization is not active", async () => {
      const prisma = buildPrisma();
      (prisma.organization.findUnique as jest.Mock).mockResolvedValue({
        id: ORG_ID,
        status: ResourceStatus.SUSPENDED,
      });
      const service = new ApiKeysService(prisma as never);

      await expect(
        service.createApiKey(adminActor, ORG_ID, {
          name: "key",
          scopes: ["proofs:read"],
        }),
      ).rejects.toThrow(ForbiddenException);
    });
  });

  // -------------------------------------------------------------------------
  // listApiKeys
  // -------------------------------------------------------------------------
  describe("listApiKeys", () => {
    it("returns metadata without keyHash", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findMany as jest.Mock).mockResolvedValue([
        { id: "key_1", name: "CI", keyPrefix: "ep_aaa_", scopes: ["proofs:read"], status: ResourceStatus.ACTIVE, lastUsedAt: null, expiresAt: null, createdAt: new Date() },
      ]);
      const service = new ApiKeysService(prisma as never);

      const result = await service.listApiKeys(adminActor, ORG_ID);

      expect(result).toHaveLength(1);
      expect(result[0]).not.toHaveProperty("keyHash");
    });

    it("isolates organizations: only queries the requested org", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findMany as jest.Mock).mockResolvedValue([]);
      const service = new ApiKeysService(prisma as never);

      await service.listApiKeys(adminActor, ORG_ID);

      expect(prisma.apiKey.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ organizationId: ORG_ID }),
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // rotateApiKey
  // -------------------------------------------------------------------------
  describe("rotateApiKey", () => {
    it("issues a new secret and invalidates the previous hash", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findFirst as jest.Mock).mockResolvedValue({ id: "key_1", status: ResourceStatus.ACTIVE });
      (prisma.apiKey.update as jest.Mock).mockResolvedValue({
        id: "key_1",
        name: "CI",
        keyPrefix: "ep_bbb_",
        scopes: ["proofs:read"],
        status: ResourceStatus.ACTIVE,
        expiresAt: null,
        createdAt: new Date(),
      });

      const service = new ApiKeysService(prisma as never);
      const result = await service.rotateApiKey(adminActor, ORG_ID, "key_1");

      expect(result.secret).toMatch(/^ep_[a-f0-9]{12}_[a-f0-9]{64}$/);
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ action: "api_key.rotated" }),
        }),
      );
    });

    it("throws NotFoundException for a key from a different org", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findFirst as jest.Mock).mockResolvedValue(null);
      const service = new ApiKeysService(prisma as never);

      await expect(
        service.rotateApiKey(adminActor, ORG_ID, "key_other_org"),
      ).rejects.toThrow(NotFoundException);
    });
  });

  // -------------------------------------------------------------------------
  // revokeApiKey
  // -------------------------------------------------------------------------
  describe("revokeApiKey", () => {
    it("sets status to REVOKED and records audit", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findFirst as jest.Mock).mockResolvedValue({ id: "key_1", status: ResourceStatus.ACTIVE });
      (prisma.apiKey.update as jest.Mock).mockResolvedValue({
        id: "key_1",
        name: "CI",
        keyPrefix: "ep_aaa_",
        status: ResourceStatus.REVOKED,
        revokedAt: new Date(),
      });

      const service = new ApiKeysService(prisma as never);
      const result = await service.revokeApiKey(adminActor, ORG_ID, "key_1");

      expect(result.status).toBe(ResourceStatus.REVOKED);
      expect(prisma.apiKey.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: ResourceStatus.REVOKED }),
        }),
      );
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ action: "api_key.revoked" }),
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // authenticate
  // -------------------------------------------------------------------------
  describe("authenticate", () => {
    function buildActiveRecord(overrides: Record<string, unknown> = {}) {
      const rawKey = "ep_aabbccddee11_" + "a".repeat(64);
      const keyHash = `sha256:${sha256(rawKey)}`;
      return {
        rawKey,
        record: {
          id: "key_1",
          organizationId: "org_1",
          keyHash,
          scopes: ["proofs:read"],
          status: ResourceStatus.ACTIVE,
          expiresAt: null,
          ...overrides,
        },
      };
    }

    it("returns a principal for a valid active key", async () => {
      const { rawKey, record } = buildActiveRecord();
      const prisma = buildPrisma();
      (prisma.apiKey.findUnique as jest.Mock).mockResolvedValue(record);
      (prisma.apiKey.update as jest.Mock).mockResolvedValue({});

      const service = new ApiKeysService(prisma as never);
      const principal = await service.authenticate(rawKey);

      expect(principal).toEqual({
        keyId: "key_1",
        organizationId: "org_1",
        scopes: ["proofs:read"],
      });
    });

    it("throws UnauthorizedException for an unknown key", async () => {
      const prisma = buildPrisma();
      (prisma.apiKey.findUnique as jest.Mock).mockResolvedValue(null);

      const service = new ApiKeysService(prisma as never);

      await expect(service.authenticate("ep_bad_key")).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it("throws UnauthorizedException for a revoked key", async () => {
      const { rawKey, record } = buildActiveRecord({ status: ResourceStatus.REVOKED });
      const prisma = buildPrisma();
      (prisma.apiKey.findUnique as jest.Mock).mockResolvedValue(record);

      const service = new ApiKeysService(prisma as never);
      await expect(service.authenticate(rawKey)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it("throws UnauthorizedException for an expired key", async () => {
      const { rawKey, record } = buildActiveRecord({
        expiresAt: new Date(Date.now() - 1000),
      });
      const prisma = buildPrisma();
      (prisma.apiKey.findUnique as jest.Mock).mockResolvedValue(record);

      const service = new ApiKeysService(prisma as never);
      await expect(service.authenticate(rawKey)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it("throws UnauthorizedException for a missing/empty key", async () => {
      const prisma = buildPrisma();
      const service = new ApiKeysService(prisma as never);

      await expect(service.authenticate("")).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it("does not leak raw key material in error messages", async () => {
      const rawKey = "ep_secret_key_material_" + "x".repeat(64);
      const prisma = buildPrisma();
      (prisma.apiKey.findUnique as jest.Mock).mockResolvedValue(null);

      const service = new ApiKeysService(prisma as never);
      try {
        await service.authenticate(rawKey);
        fail("Expected to throw");
      } catch (e) {
        expect((e as Error).message).not.toContain(rawKey);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Key hashing — never store raw material
  // -------------------------------------------------------------------------
  describe("key hashing", () => {
    it("two different keys produce different hashes (no collision)", async () => {
      const hashes = new Set<string>();

      // Create two keys by capturing what gets stored
      for (let i = 0; i < 2; i++) {
        const prisma = buildPrisma();
        (prisma.apiKey.create as jest.Mock).mockImplementation(
          async ({ data }: { data: { keyHash: string } }) => {
            hashes.add(data.keyHash);
            return { id: `key_${i}`, name: "k", keyPrefix: "ep_aaa_", scopes: [], status: ResourceStatus.ACTIVE, expiresAt: null, createdAt: new Date() };
          },
        );
        const service = new ApiKeysService(prisma as never);
        await service.createApiKey(adminActor, ORG_ID, { name: "k", scopes: ["proofs:read"] });
      }

      expect(hashes.size).toBe(2);
    });
  });
});
