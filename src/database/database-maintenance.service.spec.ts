import {
  ALLOWLISTED_MAINTENANCE_TABLES,
  DatabaseMaintenanceService,
  MAINTENANCE_THRESHOLDS,
} from "./database-maintenance.service";
import { PrismaService } from "./prisma.service";
import { DependencyKind, DependencyStatus } from "../health/health.types";

describe("DatabaseMaintenanceService", () => {
  let service: DatabaseMaintenanceService;
  let mockPrisma: Partial<PrismaService>;

  beforeEach(() => {
    mockPrisma = {
      $queryRaw: jest.fn().mockResolvedValue([
        {
          relname: "User",
          n_live_tup: 10_000n,
          n_dead_tup: 500n,
          last_vacuum: new Date("2026-11-20T10:00:00Z"),
          last_autovacuum: new Date("2026-11-21T12:00:00Z"),
        },
        {
          relname: "Payment",
          n_live_tup: 50_000n,
          n_dead_tup: 1_000n,
          last_vacuum: new Date("2026-11-22T08:00:00Z"),
          last_autovacuum: null,
        },
      ]),
    };

    service = new DatabaseMaintenanceService(mockPrisma as PrismaService);
  });

  describe("Allowlist security enforcement", () => {
    it("monitors only allowlisted database tables", () => {
      expect(ALLOWLISTED_MAINTENANCE_TABLES).toContain("User");
      expect(ALLOWLISTED_MAINTENANCE_TABLES).toContain("Payment");
      expect(ALLOWLISTED_MAINTENANCE_TABLES).toContain("Proof");
      expect(ALLOWLISTED_MAINTENANCE_TABLES).toContain("AnchorIntent");
      expect(ALLOWLISTED_MAINTENANCE_TABLES).not.toContain("ArbitraryTable");
    });

    it("restricts query to allowlisted tables only", async () => {
      const report = await service.checkMaintenanceHealth();
      expect(report.tables.map((t) => t.table)).toEqual(
        expect.arrayContaining([...ALLOWLISTED_MAINTENANCE_TABLES]),
      );
      expect(report.overallStatus).toBe("ok");
    });
  });

  describe("Threshold boundary evaluation", () => {
    it("reports ok when all tables are well below thresholds", async () => {
      const res = await service.probeDependencyResult();
      expect(res.status).toBe(DependencyStatus.OK);
      expect(res.kind).toBe(DependencyKind.OPTIONAL);
    });

    it("reports warning when a table reaches warning dead tuple threshold", async () => {
      mockPrisma.$queryRaw = jest.fn().mockResolvedValue([
        {
          relname: "Payment",
          n_live_tup: 10_000n,
          n_dead_tup: 12_000n, // exceeds WARNING_DEAD_TUPLE_COUNT (10,000)
          last_vacuum: null,
          last_autovacuum: null,
        },
      ]);

      const report = await service.checkMaintenanceHealth();
      expect(report.overallStatus).toBe("warning");
      expect(report.warnings.length).toBeGreaterThan(0);

      const res = await service.probeDependencyResult();
      expect(res.status).toBe(DependencyStatus.DEGRADED);
      expect(res.reason).toBe("dead_tuples_exceeded_warning_threshold");
    });

    it("reports critical when a table exceeds critical dead tuple threshold", async () => {
      mockPrisma.$queryRaw = jest.fn().mockResolvedValue([
        {
          relname: "Proof",
          n_live_tup: 40_000n,
          n_dead_tup: 60_000n, // dead ratio = 60%, dead count = 60k >= 50k
          last_vacuum: null,
          last_autovacuum: null,
        },
      ]);

      const report = await service.checkMaintenanceHealth();
      expect(report.overallStatus).toBe("critical");

      const res = await service.probeDependencyResult();
      expect(res.status).toBe(DependencyStatus.DEGRADED);
      expect(res.reason).toBe("dead_tuples_exceeded_critical_threshold");
    });

    it("boundary check: dead tuples just below warning threshold stay ok", async () => {
      mockPrisma.$queryRaw = jest.fn().mockResolvedValue([
        {
          relname: "Payment",
          n_live_tup: 90_000n,
          n_dead_tup: 9_999n, // just below 10,000, ratio < 20%
          last_vacuum: null,
          last_autovacuum: null,
        },
      ]);

      const report = await service.checkMaintenanceHealth();
      expect(report.overallStatus).toBe("ok");
    });
  });

  describe("Resilience to unavailable statistics", () => {
    it("handles database statistics query failures gracefully without throwing", async () => {
      mockPrisma.$queryRaw = jest.fn().mockRejectedValue(new Error("permission denied for view"));

      const report = await service.checkMaintenanceHealth();
      expect(report.overallStatus).toBe("ok");
      expect(report.warnings).toContain("pg_stat_user_tables unavailable");

      const res = await service.probeDependencyResult();
      expect(res.status).toBe(DependencyStatus.OK);
    });
  });
});
