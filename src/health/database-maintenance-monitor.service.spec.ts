import { DatabaseMaintenanceMonitorService, resolveDatabaseMaintenanceSettings } from "./database-maintenance-monitor.service";
import { DatabaseMaintenanceStatus } from "./database-maintenance-monitor.service";
import { ConfigService } from "@nestjs/config";
import { MetricsRegistry } from "../common/observability/metrics.registry";

describe("resolveDatabaseMaintenanceSettings", () => {
  const createConfig = (overrides: Record<string, unknown> = {}) => {
    return {
      get: jest.fn((key: string) => {
        const fullKey = `databaseMaintenance.${key}`;
        if (fullKey in overrides) return overrides[fullKey];
        return undefined;
      }),
    } as unknown as ConfigService;
  };

  it("returns defaults when no config provided", () => {
    const config = createConfig();
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.enabled).toBe(true);
    expect(settings.warnBloatRatio).toBe(0.1);
    expect(settings.criticalBloatRatio).toBe(0.3);
    expect(settings.warnLastVacuumAgeSeconds).toBe(86_400);
    expect(settings.criticalLastVacuumAgeSeconds).toBe(604_800);
    expect(settings.warnLastAnalyzeAgeSeconds).toBe(86_400);
    expect(settings.criticalLastAnalyzeAgeSeconds).toBe(604_800);
    expect(settings.warnDeadTuples).toBe(10_000);
    expect(settings.criticalDeadTuples).toBe(100_000);
    expect(settings.sustainSamples).toBe(3);
    expect(settings.clearSamples).toBe(2);
    expect(settings.sampleTimeoutMs).toBe(5_000);
    expect(settings.minSampleIntervalMs).toBe(30_000);
    expect(settings.allowlistedTables).toEqual([]);
    expect(settings.runbook).toBe("docs/runbooks/database-maintenance-health.md");
  });

  it("allows overriding values", () => {
    const config = createConfig({
      "databaseMaintenance.enabled": false,
      "databaseMaintenance.warnBloatRatio": 0.2,
      "databaseMaintenance.criticalBloatRatio": 0.5,
      "databaseMaintenance.warnLastVacuumAgeSeconds": 172_800,
      "databaseMaintenance.criticalLastVacuumAgeSeconds": 1_209_600,
      "databaseMaintenance.warnLastAnalyzeAgeSeconds": 172_800,
      "databaseMaintenance.criticalLastAnalyzeAgeSeconds": 1_209_600,
      "databaseMaintenance.warnDeadTuples": 50_000,
      "databaseMaintenance.criticalDeadTuples": 500_000,
      "databaseMaintenance.sustainSamples": 5,
      "databaseMaintenance.clearSamples": 3,
      "databaseMaintenance.sampleTimeoutMs": 10_000,
      "databaseMaintenance.minSampleIntervalMs": 60_000,
      "databaseMaintenance.allowlistedTables": ["public.users", "public.organizations"],
      "databaseMaintenance.runbook": "custom/runbook.md",
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.enabled).toBe(false);
    expect(settings.warnBloatRatio).toBe(0.2);
    expect(settings.criticalBloatRatio).toBe(0.5);
    expect(settings.warnLastVacuumAgeSeconds).toBe(172_800);
    expect(settings.criticalLastVacuumAgeSeconds).toBe(1_209_600);
    expect(settings.warnLastAnalyzeAgeSeconds).toBe(172_800);
    expect(settings.criticalLastAnalyzeAgeSeconds).toBe(1_209_600);
    expect(settings.warnDeadTuples).toBe(50_000);
    expect(settings.criticalDeadTuples).toBe(500_000);
    expect(settings.sustainSamples).toBe(5);
    expect(settings.clearSamples).toBe(3);
    expect(settings.sampleTimeoutMs).toBe(10_000);
    expect(settings.minSampleIntervalMs).toBe(60_000);
    expect(settings.allowlistedTables).toEqual(["public.users", "public.organizations"]);
    expect(settings.runbook).toBe("custom/runbook.md");
  });

  it("clamps warnBloatRatio to valid range", () => {
    const config = createConfig({
      "databaseMaintenance.warnBloatRatio": -0.1,
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.warnBloatRatio).toBe(0.01);

    const config2 = createConfig({
      "databaseMaintenance.warnBloatRatio": 1.5,
    });
    const settings2 = resolveDatabaseMaintenanceSettings(config2);
    expect(settings2.warnBloatRatio).toBe(0.9);
  });

  it("ensures criticalBloatRatio > warnBloatRatio", () => {
    const config = createConfig({
      "databaseMaintenance.warnBloatRatio": 0.2,
      "databaseMaintenance.criticalBloatRatio": 0.15,
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.criticalBloatRatio).toBeGreaterThan(settings.warnBloatRatio);
    expect(settings.criticalBloatRatio).toBe(0.25);
  });

  it("clamps age thresholds to valid range", () => {
    const config = createConfig({
      "databaseMaintenance.warnLastVacuumAgeSeconds": 10,
      "databaseMaintenance.criticalLastVacuumAgeSeconds": 10,
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.warnLastVacuumAgeSeconds).toBe(60);
    expect(settings.criticalLastVacuumAgeSeconds).toBe(120);
  });

  it("clamps dead tuples thresholds", () => {
    const config = createConfig({
      "databaseMaintenance.warnDeadTuples": 10,
      "databaseMaintenance.criticalDeadTuples": 10,
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.warnDeadTuples).toBe(100);
    expect(settings.criticalDeadTuples).toBe(200);
  });

  it("clamps sustain and clear samples", () => {
    const config = createConfig({
      "databaseMaintenance.sustainSamples": 20,
      "databaseMaintenance.clearSamples": 20,
    });
    const settings = resolveDatabaseMaintenanceSettings(config);
    expect(settings.sustainSamples).toBe(10);
    expect(settings.clearSamples).toBe(10);
  });
});

describe("DatabaseMaintenanceMonitorService", () => {
  let service: DatabaseMaintenanceMonitorService;
  let mockPrisma: any;
  let mockConfig: any;
  let mockRegistry: MetricsRegistry;

  beforeEach(() => {
    mockRegistry = new MetricsRegistry();
    mockConfig = {
      get: jest.fn((key: string) => {
        if (key === "databaseMaintenance.enabled") return true;
        if (key === "databaseMaintenance.warnBloatRatio") return 0.1;
        if (key === "databaseMaintenance.criticalBloatRatio") return 0.3;
        if (key === "databaseMaintenance.warnLastVacuumAgeSeconds") return 86_400;
        if (key === "databaseMaintenance.criticalLastVacuumAgeSeconds") return 604_800;
        if (key === "databaseMaintenance.warnLastAnalyzeAgeSeconds") return 86_400;
        if (key === "databaseMaintenance.criticalLastAnalyzeAgeSeconds") return 604_800;
        if (key === "databaseMaintenance.warnDeadTuples") return 10_000;
        if (key === "databaseMaintenance.criticalDeadTuples") return 100_000;
        if (key === "databaseMaintenance.sustainSamples") return 3;
        if (key === "databaseMaintenance.clearSamples") return 2;
        if (key === "databaseMaintenance.sampleTimeoutMs") return 5_000;
        if (key === "databaseMaintenance.minSampleIntervalMs") return 30_000;
        if (key === "databaseMaintenance.allowlistedTables") return [];
        if (key === "databaseMaintenance.runbook") return "docs/runbooks/database-maintenance-health.md";
        return undefined;
      }),
    };

    mockPrisma = {
      $queryRawUnsafe: jest.fn(),
    };

    service = new DatabaseMaintenanceMonitorService(
      mockConfig,
      mockPrisma,
      mockRegistry,
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("when disabled", () => {
    beforeEach(() => {
      mockConfig.get.mockImplementation((key: string) => {
        if (key === "databaseMaintenance.enabled") return false;
        return undefined;
      });
      service = new DatabaseMaintenanceMonitorService(mockConfig, mockPrisma, mockRegistry);
    });

    it("returns disabled snapshot", async () => {
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("disabled");
      expect(snapshot.reason).toBe("database_maintenance_monitor_disabled");
      expect(snapshot.tables).toEqual([]);
    });

    it("blocksReadiness returns false", () => {
      expect(service.blocksReadiness()).toBe(false);
    });
  });

  describe("when enabled but database unavailable", () => {
    it("returns unknown snapshot on query error", async () => {
      mockPrisma.$queryRawUnsafe.mockRejectedValue(new Error("connection refused"));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("unknown");
      expect(snapshot.reason).toBe("database_maintenance_metrics_unavailable");
    });

    it("returns unknown snapshot on timeout", async () => {
      mockPrisma.$queryRawUnsafe.mockImplementation(
        () => new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 100))
      );
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("unknown");
      expect(snapshot.reason).toBe("database_maintenance_sample_timeout");
    });
  });

  describe("table status classification", () => {
    const now = Date.now();
    const createMockRows = (overrides: Partial<{
      liveTuples: number;
      deadTuples: number;
      lastVacuumAge: number;
      lastAnalyzeAge: number;
    }> = {}) => [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(overrides.liveTuples ?? 1000),
      dead_tuples: BigInt(overrides.deadTuples ?? 50),
      last_vacuum: overrides.lastVacuumAge ? new Date(now - overrides.lastVacuumAge * 1000) : null,
      last_analyze: overrides.lastAnalyzeAge ? new Date(now - overrides.lastAnalyzeAge * 1000) : null,
      last_autovacuum: null,
      last_autoanalyze: null,
    }];

    it("classifies healthy table as ok", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 50 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("ok");
      expect(snapshot.tables[0].status).toBe("ok");
    });

    it("classifies table with warning bloat as warning", async () => {
      // dead/live = 150/1000 = 0.15 > warn (0.1) but < critical (0.3)
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 150 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("warning");
      expect(snapshot.tables[0].status).toBe("warning");
      expect(snapshot.tables[0].bloatRatio).toBe(0.15);
    });

    it("classifies table with critical bloat as critical", async () => {
      // dead/live = 400/1000 = 0.4 > critical (0.3)
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 400 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("critical");
      expect(snapshot.tables[0].status).toBe("critical");
      expect(snapshot.tables[0].bloatRatio).toBe(0.4);
    });

    it("classifies table with overdue vacuum as warning", async () => {
      // vacuum 48h ago > warn (24h) but < critical (7d)
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 50, lastVacuumAge: 172_800 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("warning");
      expect(snapshot.tables[0].status).toBe("warning");
    });

    it("classifies table with critically overdue vacuum as critical", async () => {
      // vacuum 8d ago > critical (7d)
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 50, lastVacuumAge: 691_200 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("critical");
      expect(snapshot.tables[0].status).toBe("critical");
    });

    it("classifies table with high dead tuples as warning", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 50_000 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("warning");
      expect(snapshot.tables[0].status).toBe("warning");
      expect(snapshot.tables[0].deadTuples).toBe(50_000);
    });

    it("classifies table with critical dead tuples as critical", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(createMockRows({ liveTuples: 1000, deadTuples: 200_000 }));
      const snapshot = await service.sample();
      expect(snapshot.status).toBe("critical");
      expect(snapshot.tables[0].status).toBe("critical");
      expect(snapshot.tables[0].deadTuples).toBe(200_000);
    });

    it("handles tables with no live tuples (bloatRatio = null)", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue([{
        schema: "public",
        table: "empty_table",
        live_tuples: BigInt(0),
        dead_tuples: BigInt(0),
        last_vacuum: null,
        last_analyze: null,
        last_autovacuum: null,
        last_autoanalyze: null,
      }]);
      const snapshot = await service.sample();
      expect(snapshot.tables[0].bloatRatio).toBeNull();
      expect(snapshot.tables[0].status).toBe("unknown");
    });

    it("handles null last_vacuum and last_analyze", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue([{
        schema: "public",
        table: "new_table",
        live_tuples: BigInt(100),
        dead_tuples: BigInt(10),
        last_vacuum: null,
        last_analyze: null,
        last_autovacuum: null,
        last_autoanalyze: null,
      }]);
      const snapshot = await service.sample();
      expect(snapshot.tables[0].lastVacuumAgeSeconds).toBeNull();
      expect(snapshot.tables[0].lastAnalyzeAgeSeconds).toBeNull();
    });
  });

  describe("hysteresis", () => {
    const now = Date.now();
    const healthyRows = [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(1000),
      dead_tuples: BigInt(50),
      last_vacuum: new Date(now - 3600_000),
      last_analyze: new Date(now - 3600_000),
      last_autovacuum: null,
      last_autoanalyze: null,
    }];

    const criticalRows = [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(1000),
      dead_tuples: BigInt(400),
      last_vacuum: new Date(now - 3600_000),
      last_analyze: new Date(now - 3600_000),
      last_autovacuum: null,
      last_autoanalyze: null,
    }];

    it("requires sustainSamples consecutive critical to latch", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(criticalRows);
      
      // First critical sample
      let snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(false);
      expect(snapshot.alert.consecutiveDegraded).toBe(1);

      // Second critical sample
      snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(false);
      expect(snapshot.alert.consecutiveDegraded).toBe(2);

      // Third critical sample - should latch
      snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(true);
      expect(snapshot.alert.consecutiveDegraded).toBe(3);
      expect(service.blocksReadiness()).toBe(true);
    });

    it("requires clearSamples consecutive healthy to clear latch", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(criticalRows);
      
      // Latch the critical state
      await service.sample();
      await service.sample();
      await service.sample();
      expect(service.blocksReadiness()).toBe(true);

      // Switch to healthy
      mockPrisma.$queryRawUnsafe.mockResolvedValue(healthyRows);
      
      // First healthy sample
      let snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(true);
      expect(snapshot.alert.consecutiveHealthy).toBe(1);

      // Second healthy sample - should clear
      snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(false);
      expect(snapshot.alert.consecutiveHealthy).toBe(2);
      expect(service.blocksReadiness()).toBe(false);
    });

    it("warning does not advance or clear hysteresis", async () => {
      const warningRows = [{
        schema: "public",
        table: "users",
        live_tuples: BigInt(1000),
        dead_tuples: BigInt(150), // 0.15 ratio - warning
        last_vacuum: new Date(now - 3600_000),
        last_analyze: new Date(now - 3600_000),
        last_autovacuum: null,
        last_autoanalyze: null,
      }];

      mockPrisma.$queryRawUnsafe.mockResolvedValue(criticalRows);
      await service.sample(); // critical
      await service.sample(); // critical

      mockPrisma.$queryRawUnsafe.mockResolvedValue(warningRows);
      const snapshot = await service.sample(); // warning
      expect(snapshot.alert.consecutiveDegraded).toBe(2); // unchanged
      expect(snapshot.alert.consecutiveHealthy).toBe(0); // unchanged
    });

    it("unknown does not clear latch", async () => {
      mockPrisma.$queryRawUnsafe.mockResolvedValue(criticalRows);
      await service.sample();
      await service.sample();
      await service.sample();
      expect(service.blocksReadiness()).toBe(true);

      // Unknown (metrics unavailable)
      mockPrisma.$queryRawUnsafe.mockRejectedValue(new Error("unavailable"));
      const snapshot = await service.sample();
      expect(snapshot.alert.sustainedCritical).toBe(true); // latch maintained
      expect(snapshot.alert.consecutiveHealthy).toBe(0); // healthy streak broken
    });
  });

  describe("rate limiting", () => {
    it("returns cached snapshot within minSampleIntervalMs", async () => {
      const now = Date.now();
      const rows = [{
        schema: "public",
        table: "users",
        live_tuples: BigInt(1000),
        dead_tuples: BigInt(50),
        last_vacuum: new Date(now - 3600_000),
        last_analyze: new Date(now - 3600_000),
        last_autovacuum: null,
        last_autoanalyze: null,
      }];
      mockPrisma.$queryRawUnsafe.mockResolvedValue(rows);

      await service.sample();
      const callCount1 = mockPrisma.$queryRawUnsafe.mock.calls.length;

      // Call again immediately - should use cached
      await service.sample();
      const callCount2 = mockPrisma.$queryRawUnsafe.mock.calls.length;

      expect(callCount2).toBe(callCount1);
    });

    it("samples again after minSampleIntervalMs", async () => {
      const now = Date.now();
      const rows = [{
        schema: "public",
        table: "users",
        live_tuples: BigInt(1000),
        dead_tuples: BigInt(50),
        last_vacuum: new Date(now - 3600_000),
        last_analyze: new Date(now - 3600_000),
        last_autovacuum: null,
        last_autoanalyze: null,
      }];
      mockPrisma.$queryRawUnsafe.mockResolvedValue(rows);

      await service.sample();
      const callCount1 = mockPrisma.$queryRawUnsafe.mock.calls.length;

      // Advance time past minSampleIntervalMs (30s)
      jest.advanceTimersByTime(31_000);
      
      await service.sample();
      const callCount2 = mockPrisma.$queryRawUnsafe.mock.calls.length;

      expect(callCount2).toBe(callCount1 + 1);
    });
  });

  describe("allowlisted tables", () => {
    it("only queries allowlisted tables", async () => {
      const now = Date.now();
      const rows = [{
        schema: "public",
        table: "users",
        live_tuples: BigInt(1000),
        dead_tuples: BigInt(50),
        last_vacuum: new Date(now - 3600_000),
        last_analyze: new Date(now - 3600_000),
        last_autovacuum: null,
        last_autoanalyze: null,
      }];
      mockPrisma.$queryRawUnsafe.mockResolvedValue(rows);

      mockConfig.get.mockImplementation((key: string) => {
        if (key === "databaseMaintenance.enabled") return true;
        if (key === "databaseMaintenance.allowlistedTables") return ["public.users"];
        return undefined;
      });
      service = new DatabaseMaintenanceMonitorService(mockConfig, mockPrisma, mockRegistry);

      await service.sample();

      const query = mockPrisma.$queryRawUnsafe.mock.calls[0][0];
      expect(query).toContain("'public.users'");
    });
  });
});