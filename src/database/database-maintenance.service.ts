import { Injectable, Logger, Optional } from "@nestjs/common";
import { PrismaService } from "./prisma.service";
import {
  DependencyKind,
  DependencyResult,
  DependencyStatus,
} from "../health/health.types";
import { MetricsRegistry } from "../common/observability/metrics.registry";

/**
 * Allowlisted database tables monitored for maintenance health.
 * Security constraint: checks CANNOT enumerate arbitrary database objects.
 */
export const ALLOWLISTED_MAINTENANCE_TABLES = Object.freeze([
  "User",
  "Payment",
  "Proof",
  "AnchorIntent",
  "WebhookEndpoint",
  "AuditEvent",
  "CspViolationSummary",
] as const);

export type AllowlistedTable = (typeof ALLOWLISTED_MAINTENANCE_TABLES)[number];

export interface TableMaintenanceStats {
  table: string;
  liveTuples: number;
  deadTuples: number;
  deadTupleRatio: number;
  lastVacuum: string | null;
  lastAutovacuum: string | null;
  status: "ok" | "warning" | "critical";
}

export interface DatabaseMaintenanceReport {
  overallStatus: "ok" | "warning" | "critical";
  tables: TableMaintenanceStats[];
  warnings: string[];
  probedAt: string;
}

export const MAINTENANCE_THRESHOLDS = Object.freeze({
  WARNING_DEAD_TUPLE_RATIO: 0.2, // 20% dead tuples
  WARNING_DEAD_TUPLE_COUNT: 10_000,
  CRITICAL_DEAD_TUPLE_RATIO: 0.5, // 50% dead tuples
  CRITICAL_DEAD_TUPLE_COUNT: 50_000,
  QUERY_TIMEOUT_MS: 2_000,
});

@Injectable()
export class DatabaseMaintenanceService {
  private readonly logger = new Logger(DatabaseMaintenanceService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Optional() private readonly metrics?: MetricsRegistry,
  ) {}

  /**
   * Evaluates PostgreSQL maintenance health across strictly allowlisted tables.
   *
   * Bounded query using PostgreSQL statistics views without scanning table heaps
   * or enumerating arbitrary database objects.
   */
  async checkMaintenanceHealth(): Promise<DatabaseMaintenanceReport> {
    const allowlist = [...ALLOWLISTED_MAINTENANCE_TABLES];
    const probedAt = new Date().toISOString();

    try {
      // Query pg_stat_user_tables strictly for allowlisted tables
      const rows = (await this.prisma.$queryRaw<
        Array<{
          relname: string;
          n_live_tup: bigint | number;
          n_dead_tup: bigint | number;
          last_vacuum: Date | string | null;
          last_autovacuum: Date | string | null;
        }>
      >`
        SELECT relname, n_live_tup, n_dead_tup, last_vacuum, last_autovacuum
        FROM pg_stat_user_tables
        WHERE relname = ANY(${allowlist})
      `) || [];

      const statsMap = new Map(rows.map((r) => [r.relname, r]));
      const tables: TableMaintenanceStats[] = [];
      const warnings: string[] = [];
      let hasCritical = false;
      let hasWarning = false;

      for (const table of allowlist) {
        const row = statsMap.get(table);
        const liveTuples = row ? Number(row.n_live_tup || 0) : 0;
        const deadTuples = row ? Number(row.n_dead_tup || 0) : 0;
        const total = liveTuples + deadTuples;
        const ratio = total > 0 ? deadTuples / total : 0;

        let status: "ok" | "warning" | "critical" = "ok";

        if (
          deadTuples >= MAINTENANCE_THRESHOLDS.CRITICAL_DEAD_TUPLE_COUNT &&
          ratio >= MAINTENANCE_THRESHOLDS.CRITICAL_DEAD_TUPLE_RATIO
        ) {
          status = "critical";
          hasCritical = true;
          warnings.push(
            `Table ${table} exceeded critical dead tuple threshold: ${deadTuples} dead (${(ratio * 100).toFixed(1)}%)`,
          );
        } else if (
          deadTuples >= MAINTENANCE_THRESHOLDS.WARNING_DEAD_TUPLE_COUNT ||
          (total >= 1_000 && ratio >= MAINTENANCE_THRESHOLDS.WARNING_DEAD_TUPLE_RATIO)
        ) {
          status = "warning";
          hasWarning = true;
          warnings.push(
            `Table ${table} elevated dead tuples: ${deadTuples} dead (${(ratio * 100).toFixed(1)}%)`,
          );
        }

        tables.push({
          table,
          liveTuples,
          deadTuples,
          deadTupleRatio: parseFloat(ratio.toFixed(4)),
          lastVacuum: row?.last_vacuum ? new Date(row.last_vacuum).toISOString() : null,
          lastAutovacuum: row?.last_autovacuum ? new Date(row.last_autovacuum).toISOString() : null,
          status,
        });
      }

      const overallStatus: "ok" | "warning" | "critical" = hasCritical
        ? "critical"
        : hasWarning
          ? "warning"
          : "ok";

      return {
        overallStatus,
        tables,
        warnings,
        probedAt,
      };
    } catch (error) {
      // Graceful fallback when pg_stat_user_tables is unavailable or lacks permission
      this.logger.warn(`Database maintenance statistics unavailable: ${error}`);
      return {
        overallStatus: "ok",
        tables: allowlist.map((table) => ({
          table,
          liveTuples: 0,
          deadTuples: 0,
          deadTupleRatio: 0,
          lastVacuum: null,
          lastAutovacuum: null,
          status: "ok",
        })),
        warnings: ["pg_stat_user_tables unavailable"],
        probedAt,
      };
    }
  }

  /**
   * Produces a DependencyResult for readiness/diagnostic checks.
   * Distinguishes warnings from failures to prevent spurious outages.
   */
  async probeDependencyResult(): Promise<DependencyResult> {
    const start = Date.now();
    const report = await this.checkMaintenanceHealth();
    const durationMs = Date.now() - start;

    if (report.overallStatus === "critical") {
      return {
        name: "database_maintenance",
        kind: DependencyKind.OPTIONAL,
        status: DependencyStatus.DEGRADED,
        durationMs,
        reason: "dead_tuples_exceeded_critical_threshold",
      };
    }

    if (report.overallStatus === "warning") {
      return {
        name: "database_maintenance",
        kind: DependencyKind.OPTIONAL,
        status: DependencyStatus.DEGRADED,
        durationMs,
        reason: "dead_tuples_exceeded_warning_threshold",
      };
    }

    return {
      name: "database_maintenance",
      kind: DependencyKind.OPTIONAL,
      status: DependencyStatus.OK,
      durationMs,
    };
  }
}
