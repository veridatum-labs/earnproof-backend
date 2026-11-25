import { Injectable, Logger, Optional } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PrismaService } from "../database/prisma.service";
import {
  METRIC_NAMES,
  registerCoreMetrics,
} from "../common/observability/metrics.catalog";
import { MetricsRegistry } from "../common/observability/metrics.registry";

export type DatabaseMaintenanceStatus =
  | "ok"
  | "warning"
  | "critical"
  | "unknown"
  | "disabled";

export interface DatabaseMaintenanceThresholds {
  /** Warning threshold for table bloat ratio (dead tuples / live tuples) */
  warnBloatRatio: number;
  /** Critical threshold for table bloat ratio */
  criticalBloatRatio: number;
  /** Warning threshold for time since last vacuum (seconds) */
  warnLastVacuumAgeSeconds: number;
  /** Critical threshold for time since last vacuum (seconds) */
  criticalLastVacuumAgeSeconds: number;
  /** Warning threshold for time since last analyze (seconds) */
  warnLastAnalyzeAgeSeconds: number;
  /** Critical threshold for time since last analyze (seconds) */
  criticalLastAnalyzeAgeSeconds: number;
  /** Warning threshold for number of dead tuples */
  warnDeadTuples: number;
  /** Critical threshold for number of dead tuples */
  criticalDeadTuples: number;
  /** Number of consecutive samples at/below threshold to sustain alert */
  sustainSamples: number;
  /** Number of consecutive healthy samples to clear alert */
  clearSamples: number;
}

export interface DatabaseMaintenanceSettings extends DatabaseMaintenanceThresholds {
  enabled: boolean;
  sampleTimeoutMs: number;
  minSampleIntervalMs: number;
  /** Tables to monitor (empty = all user tables) */
  allowlistedTables: string[];
  runbook: string;
}

export interface DatabaseMaintenanceSnapshot {
  status: DatabaseMaintenanceStatus;
  reason?: string;
  tables: TableMaintenanceInfo[];
  thresholds: DatabaseMaintenanceThresholds;
  alert: {
    sustainedCritical: boolean;
    consecutiveDegraded: number;
    consecutiveHealthy: number;
    blocksReadiness: boolean;
  };
  runbook: string;
  sampledAt: string | null;
  sampleAgeMs: number | null;
}

export interface TableMaintenanceInfo {
  /** Schema name */
  schema: string;
  /** Table name */
  table: string;
  /** Live tuple count */
  liveTuples: number | null;
  /** Dead tuple count */
  deadTuples: number | null;
  /** Bloat ratio (dead / live), null if no live tuples */
  bloatRatio: number | null;
  /** Seconds since last vacuum (autovacuum or manual) */
  lastVacuumAgeSeconds: number | null;
  /** Seconds since last analyze (autoanalyze or manual) */
  lastAnalyzeAgeSeconds: number | null;
  /** Seconds since last autovacuum */
  lastAutovacuumAgeSeconds: number | null;
  /** Seconds since last autoanalyze */
  lastAutoanalyzeAgeSeconds: number | null;
  /** Instantaneous status for this table */
  status: "ok" | "warning" | "critical" | "unknown";
  /** Stable reason code if not ok */
  reason?: string;
}

export const DATABASE_MAINTENANCE_DEFAULTS: DatabaseMaintenanceSettings = {
  enabled: true,
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
  sampleTimeoutMs: 5_000,
  minSampleIntervalMs: 30_000,
  allowlistedTables: [],
  runbook: "docs/runbooks/database-maintenance-health.md",
};

export const DATABASE_MAINTENANCE_REASONS = {
  bloatWarning: "database_maintenance_bloat_warning",
  bloatCritical: "database_maintenance_bloat_critical",
  vacuumOverdueWarning: "database_maintenance_vacuum_overdue_warning",
  vacuumOverdueCritical: "database_maintenance_vacuum_overdue_critical",
  analyzeOverdueWarning: "database_maintenance_analyze_overdue_warning",
  analyzeOverdueCritical: "database_maintenance_analyze_overdue_critical",
  deadTuplesWarning: "database_maintenance_dead_tuples_warning",
  deadTuplesCritical: "database_maintenance_dead_tuples_critical",
  metricsUnavailable: "database_maintenance_metrics_unavailable",
  sampleTimeout: "database_maintenance_sample_timeout",
  notSampled: "database_maintenance_not_sampled",
  monitorDisabled: "database_maintenance_monitor_disabled",
  monitorAbsent: "database_maintenance_monitor_absent",
} as const;

interface PrismaMetricsEntry {
  name: string;
  value?: number;
}

interface PrismaMetricsJson {
  counters?: PrismaMetricsEntry[];
  gauges?: PrismaMetricsEntry[];
  histograms?: unknown[];
}

class MaintenanceSampleTimeoutError extends Error {
  constructor() {
    super("maintenance_sample_timeout");
    this.name = "MaintenanceSampleTimeoutError";
  }
}

class MaintenanceMetricsUnavailableError extends Error {
  constructor() {
    super("maintenance_metrics_unavailable");
    this.name = "MaintenanceMetricsUnavailableError";
  }
}

type ConfigGetter = Pick<ConfigService, "get">;

function asFiniteNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

export function resolveDatabaseMaintenanceSettings(
  config: ConfigGetter,
): DatabaseMaintenanceSettings {
  const get = <T>(key: string, fallback: T): T =>
    (config.get<T>(`databaseMaintenance.${key}`) ?? fallback) as T;

  const enabled = get<boolean>("enabled", DATABASE_MAINTENANCE_DEFAULTS.enabled);

  const warnBloatRatio = clampNumber(
    asFiniteNumber(get("warnBloatRatio", DATABASE_MAINTENANCE_DEFAULTS.warnBloatRatio), DATABASE_MAINTENANCE_DEFAULTS.warnBloatRatio),
    0.01,
    0.9,
  );

  const criticalBloatRatio = Math.max(
    warnBloatRatio + 0.05,
    clampNumber(
      asFiniteNumber(get("criticalBloatRatio", DATABASE_MAINTENANCE_DEFAULTS.criticalBloatRatio), DATABASE_MAINTENANCE_DEFAULTS.criticalBloatRatio),
      0.02,
      0.95,
    ),
  );

  const warnLastVacuumAgeSeconds = clampNumber(
    asFiniteNumber(get("warnLastVacuumAgeSeconds", DATABASE_MAINTENANCE_DEFAULTS.warnLastVacuumAgeSeconds), DATABASE_MAINTENANCE_DEFAULTS.warnLastVacuumAgeSeconds),
    60,
    31_536_000,
  );

  const criticalLastVacuumAgeSeconds = Math.max(
    warnLastVacuumAgeSeconds + 60,
    clampNumber(
      asFiniteNumber(get("criticalLastVacuumAgeSeconds", DATABASE_MAINTENANCE_DEFAULTS.criticalLastVacuumAgeSeconds), DATABASE_MAINTENANCE_DEFAULTS.criticalLastVacuumAgeSeconds),
      120,
      31_536_000,
    ),
  );

  const warnLastAnalyzeAgeSeconds = clampNumber(
    asFiniteNumber(get("warnLastAnalyzeAgeSeconds", DATABASE_MAINTENANCE_DEFAULTS.warnLastAnalyzeAgeSeconds), DATABASE_MAINTENANCE_DEFAULTS.warnLastAnalyzeAgeSeconds),
    60,
    31_536_000,
  );

  const criticalLastAnalyzeAgeSeconds = Math.max(
    warnLastAnalyzeAgeSeconds + 60,
    clampNumber(
      asFiniteNumber(get("criticalLastAnalyzeAgeSeconds", DATABASE_MAINTENANCE_DEFAULTS.criticalLastAnalyzeAgeSeconds), DATABASE_MAINTENANCE_DEFAULTS.criticalLastAnalyzeAgeSeconds),
      120,
      31_536_000,
    ),
  );

  const warnDeadTuples = clampNumber(
    asFiniteNumber(get("warnDeadTuples", DATABASE_MAINTENANCE_DEFAULTS.warnDeadTuples), DATABASE_MAINTENANCE_DEFAULTS.warnDeadTuples),
    100,
    10_000_000,
  );

  const criticalDeadTuples = Math.max(
    warnDeadTuples + 1,
    clampNumber(
      asFiniteNumber(get("criticalDeadTuples", DATABASE_MAINTENANCE_DEFAULTS.criticalDeadTuples), DATABASE_MAINTENANCE_DEFAULTS.criticalDeadTuples),
      200,
      10_000_000,
    ),
  );

  const allowlistedTables = get<string[]>("allowlistedTables", DATABASE_MAINTENANCE_DEFAULTS.allowlistedTables);

  return {
    enabled: enabled !== false,
    warnBloatRatio,
    criticalBloatRatio,
    warnLastVacuumAgeSeconds,
    criticalLastVacuumAgeSeconds,
    warnLastAnalyzeAgeSeconds,
    criticalLastAnalyzeAgeSeconds,
    warnDeadTuples,
    criticalDeadTuples,
    sustainSamples: clampNumber(
      asFiniteNumber(get("sustainSamples", DATABASE_MAINTENANCE_DEFAULTS.sustainSamples), DATABASE_MAINTENANCE_DEFAULTS.sustainSamples),
      1,
      10,
    ),
    clearSamples: clampNumber(
      asFiniteNumber(get("clearSamples", DATABASE_MAINTENANCE_DEFAULTS.clearSamples), DATABASE_MAINTENANCE_DEFAULTS.clearSamples),
      1,
      10,
    ),
    sampleTimeoutMs: clampNumber(
      asFiniteNumber(get("sampleTimeoutMs", DATABASE_MAINTENANCE_DEFAULTS.sampleTimeoutMs), DATABASE_MAINTENANCE_DEFAULTS.sampleTimeoutMs),
      500,
      60_000,
    ),
    minSampleIntervalMs: clampNumber(
      asFiniteNumber(get("minSampleIntervalMs", DATABASE_MAINTENANCE_DEFAULTS.minSampleIntervalMs), DATABASE_MAINTENANCE_DEFAULTS.minSampleIntervalMs),
      0,
      3_600_000,
    ),
    allowlistedTables: Array.isArray(allowlistedTables) ? allowlistedTables : [],
    runbook:
      typeof get("runbook", DATABASE_MAINTENANCE_DEFAULTS.runbook) === "string" &&
      (get("runbook", DATABASE_MAINTENANCE_DEFAULTS.runbook) as string).trim() !== ""
        ? (get("runbook", DATABASE_MAINTENANCE_DEFAULTS.runbook) as string)
        : DATABASE_MAINTENANCE_DEFAULTS.runbook,
  };
}

function classifyTableMaintenance(
  table: TableMaintenanceInfo,
  thresholds: DatabaseMaintenanceThresholds,
): "ok" | "warning" | "critical" | "unknown" {
  if (table.bloatRatio === null && table.lastVacuumAgeSeconds === null && table.lastAnalyzeAgeSeconds === null) {
    return "unknown";
  }

  let worst: "ok" | "warning" | "critical" = "ok";

  if (table.bloatRatio !== null) {
    if (table.bloatRatio >= thresholds.criticalBloatRatio) {
      worst = "critical";
    } else if (table.bloatRatio >= thresholds.warnBloatRatio && worst !== "critical") {
      worst = "warning";
    }
  }

  if (table.lastVacuumAgeSeconds !== null) {
    if (table.lastVacuumAgeSeconds >= thresholds.criticalLastVacuumAgeSeconds) {
      worst = "critical";
    } else if (table.lastVacuumAgeSeconds >= thresholds.warnLastVacuumAgeSeconds && worst !== "critical") {
      worst = "warning";
    }
  }

  if (table.lastAnalyzeAgeSeconds !== null) {
    if (table.lastAnalyzeAgeSeconds >= thresholds.criticalLastAnalyzeAgeSeconds) {
      worst = "critical";
    } else if (table.lastAnalyzeAgeSeconds >= thresholds.warnLastAnalyzeAgeSeconds && worst !== "critical") {
      worst = "warning";
    }
  }

  if (table.deadTuples !== null) {
    if (table.deadTuples >= thresholds.criticalDeadTuples) {
      worst = "critical";
    } else if (table.deadTuples >= thresholds.warnDeadTuples && worst !== "critical") {
      worst = "warning";
    }
  }

  return worst;
}

function getTableReason(
  table: TableMaintenanceInfo,
  thresholds: DatabaseMaintenanceThresholds,
): string | undefined {
  const reasons: string[] = [];

  if (table.bloatRatio !== null) {
    if (table.bloatRatio >= thresholds.criticalBloatRatio) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.bloatCritical);
    } else if (table.bloatRatio >= thresholds.warnBloatRatio) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.bloatWarning);
    }
  }

  if (table.lastVacuumAgeSeconds !== null) {
    if (table.lastVacuumAgeSeconds >= thresholds.criticalLastVacuumAgeSeconds) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.vacuumOverdueCritical);
    } else if (table.lastVacuumAgeSeconds >= thresholds.warnLastVacuumAgeSeconds) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.vacuumOverdueWarning);
    }
  }

  if (table.lastAnalyzeAgeSeconds !== null) {
    if (table.lastAnalyzeAgeSeconds >= thresholds.criticalLastAnalyzeAgeSeconds) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.analyzeOverdueCritical);
    } else if (table.lastAnalyzeAgeSeconds >= thresholds.warnLastAnalyzeAgeSeconds) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.analyzeOverdueWarning);
    }
  }

  if (table.deadTuples !== null) {
    if (table.deadTuples >= thresholds.criticalDeadTuples) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.deadTuplesCritical);
    } else if (table.deadTuples >= thresholds.warnDeadTuples) {
      reasons.push(DATABASE_MAINTENANCE_REASONS.deadTuplesWarning);
    }
  }

  return reasons.length > 0 ? reasons.sort().join(",") : undefined;
}

function computeOverallStatus(
  tables: TableMaintenanceInfo[],
  thresholds: DatabaseMaintenanceThresholds,
  sustainedCritical: boolean,
): DatabaseMaintenanceStatus {
  if (tables.length === 0) return "unknown";

  let hasCritical = false;
  let hasWarning = false;
  let hasUnknown = false;

  for (const table of tables) {
    const status = classifyTableMaintenance(table, thresholds);
    if (status === "critical") hasCritical = true;
    else if (status === "warning") hasWarning = true;
    else if (status === "unknown") hasUnknown = true;
  }

  if (sustainedCritical) return "critical";
  if (hasCritical) return "critical";
  if (hasWarning) return "warning";
  if (hasUnknown) return "unknown";
  return "ok";
}

function getOverallReason(
  tables: TableMaintenanceInfo[],
  thresholds: DatabaseMaintenanceThresholds,
  sustainedCritical: boolean,
): string | undefined {
  if (sustainedCritical) {
    return DATABASE_MAINTENANCE_REASONS.bloatCritical;
  }

  const reasons = new Set<string>();
  for (const table of tables) {
    const reason = getTableReason(table, thresholds);
    if (reason) {
      for (const r of reason.split(",")) {
        reasons.add(r);
      }
    }
  }

  return reasons.size > 0 ? [...reasons].sort().join(",") : undefined;
}

@Injectable()
export class DatabaseMaintenanceMonitorService {
  private readonly logger = new Logger(DatabaseMaintenanceMonitorService.name);
  private readonly settings: DatabaseMaintenanceSettings;

  private lastSnapshot: DatabaseMaintenanceSnapshot | null = null;
  private lastSampledAtMs: number | null = null;
  private inFlight: Promise<DatabaseMaintenanceSnapshot> | null = null;

  private consecutiveDegraded = 0;
  private consecutiveHealthy = 0;
  private sustainedCritical = false;

  constructor(
    private readonly config: ConfigService,
    @Optional() private readonly prisma?: PrismaService,
    @Optional() private readonly registry?: MetricsRegistry,
  ) {
    this.settings = resolveDatabaseMaintenanceSettings(config);
    if (this.registry) {
      try {
        registerCoreMetrics(this.registry);
      } catch (error) {
        this.logger.warn(
          `Maintenance metrics catalog registration failed: ${error instanceof Error ? error.name : "unknown"}`,
        );
      }
    }
  }

  get enabled(): boolean {
    return this.settings.enabled;
  }

  get thresholds(): DatabaseMaintenanceThresholds {
    const {
      warnBloatRatio,
      criticalBloatRatio,
      warnLastVacuumAgeSeconds,
      criticalLastVacuumAgeSeconds,
      warnLastAnalyzeAgeSeconds,
      criticalLastAnalyzeAgeSeconds,
      warnDeadTuples,
      criticalDeadTuples,
      sustainSamples,
      clearSamples,
    } = this.settings;
    return {
      warnBloatRatio,
      criticalBloatRatio,
      warnLastVacuumAgeSeconds,
      criticalLastVacuumAgeSeconds,
      warnLastAnalyzeAgeSeconds,
      criticalLastAnalyzeAgeSeconds,
      warnDeadTuples,
      criticalDeadTuples,
      sustainSamples,
      clearSamples,
    };
  }

  blocksReadiness(): boolean {
    return this.settings.enabled && this.sustainedCritical;
  }

  sample(nowMs: number = Date.now()): Promise<DatabaseMaintenanceSnapshot> {
    if (!this.settings.enabled) {
      return Promise.resolve(this.buildSnapshot("disabled", DATABASE_MAINTENANCE_REASONS.monitorDisabled, nowMs, []));
    }
    if (
      this.lastSnapshot !== null &&
      this.lastSampledAtMs !== null &&
      nowMs - this.lastSampledAtMs < this.settings.minSampleIntervalMs
    ) {
      return Promise.resolve(this.refreshSnapshot(nowMs));
    }
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.sampleOnce(nowMs).finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  snapshot(nowMs: number = Date.now()): DatabaseMaintenanceSnapshot {
    if (this.lastSnapshot) return this.refreshSnapshot(nowMs);
    return this.buildSnapshot("unknown", DATABASE_MAINTENANCE_REASONS.notSampled, nowMs, []);
  }

  private async sampleOnce(nowMs: number): Promise<DatabaseMaintenanceSnapshot> {
    let tables: TableMaintenanceInfo[];
    try {
      tables = await this.readMaintenanceMetricsWithTimeout();
    } catch (error) {
      if (error instanceof MaintenanceSampleTimeoutError) {
        this.consecutiveHealthy = 0;
        const snapshot = this.buildSnapshot("unknown", DATABASE_MAINTENANCE_REASONS.sampleTimeout, nowMs, []);
        this.storeSnapshot(snapshot, nowMs);
        return snapshot;
      }
      this.logger.warn(
        `Database maintenance metrics unavailable: ${error instanceof Error ? error.name : "unknown"}`,
      );
      this.consecutiveHealthy = 0;
      const snapshot = this.buildSnapshot("unknown", DATABASE_MAINTENANCE_REASONS.metricsUnavailable, nowMs, []);
      this.storeSnapshot(snapshot, nowMs);
      return snapshot;
    }

    const instantaneous = computeOverallStatus(tables, this.settings, false);
    this.advanceHysteresis(instantaneous);

    const status: DatabaseMaintenanceStatus = this.sustainedCritical ? "critical" : instantaneous;
    const reason = getOverallReason(tables, this.settings, this.sustainedCritical);

    const snapshot = this.buildSnapshot(status, reason, nowMs, tables);
    this.storeSnapshot(snapshot, nowMs);
    this.emitMetrics(snapshot);
    return snapshot;
  }

  private advanceHysteresis(instantaneous: "ok" | "warning" | "critical" | "unknown"): void {
    if (instantaneous === "critical") {
      this.consecutiveDegraded += 1;
      this.consecutiveHealthy = 0;
      if (this.consecutiveDegraded >= this.settings.sustainSamples) {
        this.sustainedCritical = true;
      }
    } else if (instantaneous === "ok") {
      this.consecutiveHealthy += 1;
      this.consecutiveDegraded = 0;
      if (this.consecutiveHealthy >= this.settings.clearSamples) {
        this.sustainedCritical = false;
      }
    }
    // "warning" and "unknown" leave counters untouched
  }

  private async readMaintenanceMetricsWithTimeout(): Promise<TableMaintenanceInfo[]> {
    const client = this.prisma;
    if (!client) {
      throw new MaintenanceMetricsUnavailableError();
    }

    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new MaintenanceSampleTimeoutError());
        }, this.settings.sampleTimeoutMs);
      });

      const query = this.buildMaintenanceQuery();
      const result = await Promise.race([
        client.$queryRawUnsafe<Array<{
          schema: string;
          table: string;
          live_tuples: bigint | null;
          dead_tuples: bigint | null;
          last_vacuum: Date | null;
          last_analyze: Date | null;
          last_autovacuum: Date | null;
          last_autoanalyze: Date | null;
        }>>(query),
        timeout,
      ]);

      return this.parseMaintenanceResult(result);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private buildMaintenanceQuery(): string {
    // Query pg_stat_user_tables for maintenance statistics
    // Only includes tables from allowlist if configured, otherwise all user tables
    const allowlistClause = this.settings.allowlistedTables.length > 0
      ? `AND schemaname || '.' || relname IN (${this.settings.allowlistedTables.map(t => `'${t}'`).join(",")})`
      : "";

    return `
      SELECT
        schemaname as schema,
        relname as table,
        n_live_tup as live_tuples,
        n_dead_tup as dead_tuples,
        last_vacuum,
        last_analyze,
        last_autovacuum,
        last_autoanalyze
      FROM pg_stat_user_tables
      WHERE schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
      ${allowlistClause}
      ORDER BY schemaname, relname
    `;
  }

  private parseMaintenanceResult(rows: Array<{
    schema: string;
    table: string;
    live_tuples: bigint | null;
    dead_tuples: bigint | null;
    last_vacuum: Date | null;
    last_analyze: Date | null;
    last_autovacuum: Date | null;
    last_autoanalyze: Date | null;
  }>): TableMaintenanceInfo[] {
    const now = Date.now();
    return rows.map((row) => {
      const liveTuples = row.live_tuples !== null ? Number(row.live_tuples) : null;
      const deadTuples = row.dead_tuples !== null ? Number(row.dead_tuples) : null;
      const bloatRatio = liveTuples !== null && liveTuples > 0 && deadTuples !== null
        ? deadTuples / liveTuples
        : null;

      const lastVacuumAgeSeconds = row.last_vacuum
        ? Math.floor((now - row.last_vacuum.getTime()) / 1000)
        : null;
      const lastAnalyzeAgeSeconds = row.last_analyze
        ? Math.floor((now - row.last_analyze.getTime()) / 1000)
        : null;
      const lastAutovacuumAgeSeconds = row.last_autovacuum
        ? Math.floor((now - row.last_autovacuum.getTime()) / 1000)
        : null;
      const lastAutoanalyzeAgeSeconds = row.last_autoanalyze
        ? Math.floor((now - row.last_autoanalyze.getTime()) / 1000)
        : null;

      const tableInfo: TableMaintenanceInfo = {
        schema: row.schema,
        table: row.table,
        liveTuples,
        deadTuples,
        bloatRatio,
        lastVacuumAgeSeconds,
        lastAnalyzeAgeSeconds,
        lastAutovacuumAgeSeconds,
        lastAutoanalyzeAgeSeconds,
        status: "unknown",
      };

      tableInfo.status = classifyTableMaintenance(tableInfo, this.settings);
      tableInfo.reason = getTableReason(tableInfo, this.settings);

      return tableInfo;
    });
  }

  private emitMetrics(snapshot: DatabaseMaintenanceSnapshot): void {
    if (!this.registry) return;

    try {
      // Emit per-table metrics
      for (const table of snapshot.tables) {
        // Map table name and schema to allowed label values
        const tableLabel = this.mapTableToLabel(table.table);
        const schemaLabel = this.mapSchemaToLabel(table.schema);
        const labels = {
          schema: schemaLabel,
          table: tableLabel,
        };

        if (table.bloatRatio !== null) {
          this.registry.observe(METRIC_NAMES.databaseMaintenanceBloatRatio, table.bloatRatio, labels);
        }
        if (table.deadTuples !== null) {
          this.registry.observe(METRIC_NAMES.databaseMaintenanceDeadTuples, table.deadTuples, labels);
        }
        if (table.lastVacuumAgeSeconds !== null) {
          this.registry.observe(METRIC_NAMES.databaseMaintenanceLastVacuumAgeSeconds, table.lastVacuumAgeSeconds, labels);
        }
        if (table.lastAnalyzeAgeSeconds !== null) {
          this.registry.observe(METRIC_NAMES.databaseMaintenanceLastAnalyzeAgeSeconds, table.lastAnalyzeAgeSeconds, labels);
        }
      }

      // Emit overall status
      this.registry.increment(METRIC_NAMES.databaseMaintenanceStatusTotal, {
        status: snapshot.status,
      });
    } catch {
      // Observability must never break health reporting
    }
  }

  private mapTableToLabel(tableName: string): string {
    // Known tables that are explicitly allowed in the label vocabulary
    const knownTables = new Set([
      "users",
      "organizations",
      "issuers",
      "payments",
      "proofs",
      "attestations",
      "webhooks",
      "api_keys",
      "auth_sessions",
      "trusted_sources",
      "supported_assets",
      "idempotency_records",
      "verification_events",
      "anchoring_intents",
      "proof_sharing_events",
      "credential_quarantines",
      "purpose_declarations",
      "verification_policies",
    ]);
    // Remove schema prefix if present (e.g., "public.users" -> "users")
    const simpleName = tableName.includes(".") ? tableName.split(".").pop()! : tableName;
    return knownTables.has(simpleName) ? simpleName : "other";
  }

  private mapSchemaToLabel(schemaName: string): string {
    return schemaName === "public" ? "public" : "other";
  }

  private storeSnapshot(snapshot: DatabaseMaintenanceSnapshot, nowMs: number): void {
    this.lastSnapshot = snapshot;
    this.lastSampledAtMs = nowMs;
  }

  private refreshSnapshot(nowMs: number): DatabaseMaintenanceSnapshot {
    if (!this.lastSnapshot || this.lastSampledAtMs === null) {
      return this.snapshot(nowMs);
    }
    return {
      ...this.lastSnapshot,
      alert: {
        sustainedCritical: this.sustainedCritical,
        consecutiveDegraded: this.consecutiveDegraded,
        consecutiveHealthy: this.consecutiveHealthy,
        blocksReadiness: this.blocksReadiness(),
      },
      sampleAgeMs: Math.max(0, nowMs - this.lastSampledAtMs),
    };
  }

  private buildSnapshot(
    status: DatabaseMaintenanceStatus,
    reason: string | undefined,
    nowMs: number,
    tables: TableMaintenanceInfo[],
    sampledAtMs: number | null = nowMs,
  ): DatabaseMaintenanceSnapshot {
    return {
      status,
      ...(reason ? { reason } : {}),
      tables,
      thresholds: this.thresholds,
      alert: {
        sustainedCritical: this.sustainedCritical,
        consecutiveDegraded: this.consecutiveDegraded,
        consecutiveHealthy: this.consecutiveHealthy,
        blocksReadiness: this.blocksReadiness(),
      },
      runbook: this.settings.runbook,
      sampledAt: sampledAtMs === null ? null : new Date(sampledAtMs).toISOString(),
      sampleAgeMs: sampledAtMs === null ? null : Math.max(0, nowMs - sampledAtMs),
    };
  }
}