import { Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PrismaService } from "../database/prisma.service";
import { DatabaseMaintenanceMonitorService } from "./database-maintenance-monitor.service";
import { DependencyStatus } from "./health.types";
import { HealthService } from "./health.service";

interface ConfigOverrides {
  [key: string]: unknown;
}

function buildConfig(overrides: ConfigOverrides = {}): ConfigService {
  const base: ConfigOverrides = {
    databaseUrl: "postgresql://user:hunter2@db.internal:5432/earnproof",
    sessionSecret: "session-secret",
    credentialSigningSecret: "signing-secret",
    "stellar.horizonUrl": "https://horizon-testnet.stellar.org",
    "contractAnchoring.enabled": false,
    "health.probeTimeoutMs": 50,
    "health.cacheTtlMs": 0,
    "databaseMaintenance.enabled": true,
    "databaseMaintenance.warnBloatRatio": 0.1,
    "databaseMaintenance.criticalBloatRatio": 0.3,
    "databaseMaintenance.warnLastVacuumAgeSeconds": 86_400,
    "databaseMaintenance.criticalLastVacuumAgeSeconds": 604_800,
    "databaseMaintenance.warnLastAnalyzeAgeSeconds": 86_400,
    "databaseMaintenance.criticalLastAnalyzeAgeSeconds": 604_800,
    "databaseMaintenance.warnDeadTuples": 10_000,
    "databaseMaintenance.criticalDeadTuples": 100_000,
    "databaseMaintenance.sustainSamples": 3,
    "databaseMaintenance.clearSamples": 2,
    "databaseMaintenance.sampleTimeoutMs": 5_000,
    "databaseMaintenance.minSampleIntervalMs": 0,
    "databaseMaintenance.allowlistedTables": [],
    "databaseMaintenance.runbook": "docs/runbooks/database-maintenance-health.md",
  };
  const merged = { ...base, ...overrides };
  return {
    get: jest.fn((key: string) => merged[key]),
  } as unknown as ConfigService;
}

function buildPrisma(overrides: Partial<PrismaService> = {}): PrismaService {
  return {
    $queryRaw: jest.fn().mockResolvedValue([{ "?column?": 1 }]),
    webhookDelivery: { count: jest.fn().mockResolvedValue(0) },
    ...overrides,
  } as unknown as PrismaService;
}

function maintenancePayload(overrides: {
  tables?: Array<{
    schema: string;
    table: string;
    live_tuples: bigint;
    dead_tuples: bigint;
    last_vacuum: Date | null;
    last_analyze: Date | null;
    last_autovacuum: Date | null;
    last_autoanalyze: Date | null;
  }>;
} = {}) {
  const now = Date.now();
  const defaultTables = [{
    schema: "public",
    table: "users",
    live_tuples: BigInt(1000),
    dead_tuples: BigInt(50),
    last_vacuum: new Date(now - 3600_000),
    last_analyze: new Date(now - 3600_000),
    last_autovacuum: null,
    last_autoanalyze: null,
  }];
  return overrides.tables ?? defaultTables;
}

function criticalMaintenancePayload() {
  const now = Date.now();
  return {
    tables: [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(1000),
      dead_tuples: BigInt(400), // bloat ratio 0.4 > critical 0.3
      last_vacuum: new Date(now - 3600_000),
      last_analyze: new Date(now - 3600_000),
      last_autovacuum: null,
      last_autoanalyze: null,
    }],
  };
}

function warningMaintenancePayload() {
  const now = Date.now();
  return {
    tables: [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(1000),
      dead_tuples: BigInt(150), // bloat ratio 0.15 > warn 0.1 but < critical 0.3
      last_vacuum: new Date(now - 3600_000),
      last_analyze: new Date(now - 3600_000),
      last_autovacuum: null,
      last_autoanalyze: null,
    }],
  };
}

function overdueVacuumPayload() {
  const now = Date.now();
  return {
    tables: [{
      schema: "public",
      table: "users",
      live_tuples: BigInt(1000),
      dead_tuples: BigInt(50),
      last_vacuum: new Date(now - 172_800_000), // 48h ago > warn 24h
      last_analyze: new Date(now - 3600_000),
      last_autovacuum: null,
      last_autoanalyze: null,
    }],
  };
}

function buildMaintenanceMonitor(
  config: ConfigService,
  prisma: PrismaService,
): DatabaseMaintenanceMonitorService {
  return new DatabaseMaintenanceMonitorService(config, prisma);
}

function attachMaintenanceMetrics(prisma: PrismaService, payload: unknown): void {
  (prisma as unknown as Record<string, unknown>).$queryRawUnsafe = jest.fn().mockResolvedValue(payload.tables);
}

describe("HealthService — database maintenance health", () => {
  beforeEach(() => {
    jest.spyOn(Logger.prototype, "warn").mockImplementation(() => undefined);
    jest.spyOn(Logger.prototype, "error").mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("readiness", () => {
    it("stays ready on a single critical maintenance sample (hysteresis)", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, criticalMaintenancePayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkReadiness();

      expect(result.status).toBe("ready");
      expect(result.dependencies.find((d) => d.name === "database_maintenance")).toBeUndefined();
    });

    it("is not ready with a database_maintenance dependency after sustained critical", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, criticalMaintenancePayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      await service.checkReadiness();
      await service.checkReadiness();
      const result = await service.checkReadiness();

      expect(result.status).toBe("not_ready");
      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep).toBeDefined();
      expect(maintDep?.status).toBe(DependencyStatus.ERROR);
      expect(maintDep?.reason).toBe("database_maintenance_bloat_critical");
      expect(maintDep?.kind).toBe("required");
      expect(maintDep?.maintenance?.status).toBe("critical");
      expect(maintDep?.maintenance?.thresholds.criticalBloatRatio).toBe(0.3);
      expect(maintDep?.maintenance?.runbook).toBe("docs/runbooks/database-maintenance-health.md");
    });

    it("does not sample maintenance when the database probe fails", async () => {
      const config = buildConfig();
      const prisma = buildPrisma({
        $queryRaw: jest.fn().mockRejectedValue(new Error("connection refused")),
      });
      const queryRawUnsafe = jest.fn().mockResolvedValue(criticalMaintenancePayload().tables);
      (prisma as unknown as Record<string, unknown>).$queryRawUnsafe = queryRawUnsafe;
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkReadiness();

      expect(result.status).toBe("not_ready");
      expect(result.dependencies.find((d) => d.name === "database")).toBeDefined();
      expect(result.dependencies.find((d) => d.name === "database_maintenance")).toBeUndefined();
      expect(queryRawUnsafe).not.toHaveBeenCalled();
    });

    it("behaves as before when no maintenance monitor is wired (regression)", async () => {
      const service = new HealthService(buildPrisma(), buildConfig());
      const result = await service.checkReadiness();
      expect(result.status).toBe("ready");
      expect(result.dependencies.find((d) => d.name === "database_maintenance")).toBeUndefined();
    });

    it("warns but stays ready when maintenance is in warning state", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, warningMaintenancePayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkReadiness();

      expect(result.status).toBe("ready");
      expect(result.dependencies.find((d) => d.name === "database_maintenance")).toBeUndefined();
    });
  });

  describe("diagnostics", () => {
    it("exposes the maintenance snapshot with thresholds and runbook, and no credentials", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, maintenancePayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep).toBeDefined();
      expect(maintDep?.status).toBe(DependencyStatus.OK);
      expect(maintDep?.kind).toBe("optional");
      expect(maintDep?.maintenance?.tables).toHaveLength(1);
      expect(maintDep?.maintenance?.tables[0].schema).toBe("public");
      expect(maintDep?.maintenance?.tables[0].table).toBe("users");
      expect(maintDep?.maintenance?.tables[0].bloatRatio).toBe(0.05);
      expect(maintDep?.maintenance?.thresholds).toEqual({
        warnBloatRatio: 0.1,
        criticalBloatRatio: 0.3,
        warnLastVacuumAgeSeconds: 86_400,
        criticalLastVacuumAgeSeconds: 604_800,
        warnLastAnalyzeAgeSeconds: 86_400,
        criticalLastAnalyzeAgeSeconds: 604_800,
        warnDeadTuples: 10_000,
        criticalDeadTuples: 100_000,
        sustainSamples: 3,
        clearSamples: 2,
      });
      expect(maintDep?.maintenance?.runbook).toBe("docs/runbooks/database-maintenance-health.md");
      expect(JSON.stringify(result)).not.toContain("hunter2");
      expect(JSON.stringify(result)).not.toContain("db.internal");
      expect(JSON.stringify(result)).not.toContain("postgresql://");
    });

    it("reports a warning maintenance as degraded without blocking the verdict", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, warningMaintenancePayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      expect(result.status).toBe("ready");
      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.status).toBe(DependencyStatus.DEGRADED);
      expect(maintDep?.reason).toBe("database_maintenance_bloat_warning");
      expect(maintDep?.kind).toBe("optional");
    });

    it("reports overdue vacuum as degraded", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      attachMaintenanceMetrics(prisma, overdueVacuumPayload());
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      expect(result.status).toBe("ready");
      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.status).toBe(DependencyStatus.DEGRADED);
      expect(maintDep?.reason).toContain("database_maintenance_vacuum_overdue_warning");
      expect(maintDep?.kind).toBe("optional");
    });

    it("reports not_configured when no maintenance monitor is wired", async () => {
      const service = new HealthService(buildPrisma(), buildConfig());
      const result = await service.checkDiagnostics();
      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep).toBeDefined();
      expect(maintDep?.status).toBe(DependencyStatus.NOT_CONFIGURED);
      expect(maintDep?.reason).toBe("database_maintenance_monitor_absent");
    });

    it("reports unknown maintenance state as degraded when metrics are unavailable", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      (prisma as unknown as Record<string, unknown>).$queryRawUnsafe = jest.fn().mockRejectedValue(new Error("Can't reach database server"));
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.status).toBe(DependencyStatus.DEGRADED);
      expect(maintDep?.reason).toBe("database_maintenance_metrics_unavailable");
      expect(JSON.stringify(result)).not.toContain("Can't reach database server");
      expect(result.status).toBe("ready");
    });

    it("includes table-level detail in diagnostics", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      const now = Date.now();
      const multiTablePayload = {
        tables: [
          {
            schema: "public",
            table: "users",
            live_tuples: BigInt(1000),
            dead_tuples: BigInt(50),
            last_vacuum: new Date(now - 3600_000),
            last_analyze: new Date(now - 3600_000),
            last_autovacuum: null,
            last_autoanalyze: null,
          },
          {
            schema: "public",
            table: "organizations",
            live_tuples: BigInt(500),
            dead_tuples: BigInt(200), // bloat ratio 0.4 - critical
            last_vacuum: new Date(now - 3600_000),
            last_analyze: new Date(now - 3600_000),
            last_autovacuum: null,
            last_autoanalyze: null,
          },
        ],
      };
      attachMaintenanceMetrics(prisma, multiTablePayload);
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.maintenance?.tables).toHaveLength(2);
      expect(maintDep?.maintenance?.tables[0].status).toBe("ok");
      expect(maintDep?.maintenance?.tables[1].status).toBe("critical");
      expect(maintDep?.maintenance?.tables[1].bloatRatio).toBe(0.4);
    });
  });

  describe("when maintenance monitor is disabled", () => {
    it("reports disabled in diagnostics", async () => {
      const config = buildConfig({ "databaseMaintenance.enabled": false });
      const service = new HealthService(buildPrisma(), config);
      const result = await service.checkDiagnostics();
      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.status).toBe(DependencyStatus.DISABLED);
      expect(maintDep?.reason).toBe("database_maintenance_monitor_disabled");
    });

    it("does not affect readiness when disabled", async () => {
      const config = buildConfig({ "databaseMaintenance.enabled": false });
      const service = new HealthService(buildPrisma(), config);
      const result = await service.checkReadiness();
      expect(result.status).toBe("ready");
      expect(result.dependencies.find((d) => d.name === "database_maintenance")).toBeUndefined();
    });
  });

  describe("multiple tables", () => {
    it("overall status is worst of all tables", async () => {
      const config = buildConfig();
      const prisma = buildPrisma();
      const now = Date.now();
      const payload = {
        tables: [
          {
            schema: "public",
            table: "users",
            live_tuples: BigInt(1000),
            dead_tuples: BigInt(50),
            last_vacuum: new Date(now - 3600_000),
            last_analyze: new Date(now - 3600_000),
            last_autovacuum: null,
            last_autoanalyze: null,
          },
          {
            schema: "public",
            table: "payments",
            live_tuples: BigInt(1000),
            dead_tuples: BigInt(400), // critical bloat
            last_vacuum: new Date(now - 3600_000),
            last_analyze: new Date(now - 3600_000),
            last_autovacuum: null,
            last_autoanalyze: null,
          },
        ],
      };
      attachMaintenanceMetrics(prisma, payload);
      const maintenance = buildMaintenanceMonitor(config, prisma);
      const service = new HealthService(prisma, config, undefined, undefined, undefined, undefined, maintenance);

      const result = await service.checkDiagnostics();

      const maintDep = result.dependencies.find((d) => d.name === "database_maintenance");
      expect(maintDep?.maintenance?.status).toBe("critical");
      expect(maintDep?.maintenance?.tables).toHaveLength(2);
    });
  });
});