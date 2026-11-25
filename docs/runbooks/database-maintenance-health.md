# Runbook: Database maintenance health

## What fired

| Alert | Condition | Severity | Owner |
|---|---|---|---|
| Table bloat warning | `database_maintenance_bloat_ratio` > 0.1 on any table | **P2** | Platform on-call |
| Table bloat critical | `database_maintenance_bloat_ratio` > 0.3 on any table | **P1** | Platform on-call |
| Vacuum overdue warning | `database_maintenance_last_vacuum_age_seconds` > 86,400 (24h) | **P2** | Platform on-call |
| Vacuum overdue critical | `database_maintenance_last_vacuum_age_seconds` > 604,800 (7d) | **P1** | Platform on-call |
| Analyze overdue warning | `database_maintenance_last_analyze_age_seconds` > 86,400 (24h) | **P2** | Platform on-call |
| Analyze overdue critical | `database_maintenance_last_analyze_age_seconds` > 604,800 (7d) | **P1** | Platform on-call |
| Dead tuples warning | `database_maintenance_dead_tuples` > 10,000 | **P2** | Platform on-call |
| Dead tuples critical | `database_maintenance_dead_tuples` > 100,000 | **P1** | Platform on-call |

The maintenance monitor samples `pg_stat_user_tables` at most once per 30 seconds
(minSampleIntervalMs). Readiness fails only after 3 consecutive degraded samples
(sustainSamples) — not on a single spike.

The bounded snapshot (per-table bloat, vacuum/analyze age, dead tuples, thresholds,
hysteresis state) is available at `GET /health/diagnostics` under `database_maintenance`
(ADMIN authorization required).

## Diagnose

### 1. Which table(s) are affected?

```
# Tables with high bloat
database_maintenance_bloat_ratio > 0.1

# Tables with overdue vacuum
database_maintenance_last_vacuum_age_seconds > 86400

# Tables with overdue analyze
database_maintenance_last_analyze_age_seconds > 86400

# Tables with high dead tuples
database_maintenance_dead_tuples > 10000
```

Use the `schema` and `table` labels to identify the specific table(s).

### 2. Is autovacuum running?

```sql
SELECT pid, datname, usename, query_start, state, query
FROM pg_stat_activity
WHERE query LIKE '%autovacuum%';
```

- If no autovacuum processes are visible, autovacuum may be disabled or blocked.
- Check `autovacuum` setting: `SHOW autovacuum;`
- Check per-table autovacuum settings: `SELECT relname, reloptions FROM pg_class WHERE reloptions IS NOT NULL;`

### 3. Is there a long-running transaction blocking vacuum?

```sql
SELECT pid, usename, datname, state, query_start, query
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND query_start < now() - interval '1 hour';
```

Long-running transactions prevent vacuum from removing dead tuples.

### 4. Is the table heavily updated/deleted?

High dead tuple counts with recent vacuum activity indicate high churn:
- Check application workload for bulk updates/deletes.
- Consider lowering `autovacuum_vacuum_scale_factor` and `autovacuum_analyze_scale_factor` for the table.

```sql
ALTER TABLE public.<table> SET (autovacuum_vacuum_scale_factor = 0.05);
```

### 5. Are there many tables affected?

If multiple tables show degradation simultaneously, it may indicate:
- Autovacuum not running globally
- Instance-level resource pressure (CPU, I/O)
- A recent large migration or data load

## Mitigate

| Cause | Action |
|---|---|
| Autovacuum disabled | Enable: `ALTER SYSTEM SET autovacuum = on;` and reload. |
| Autovacuum blocked by long transaction | Terminate the blocking transaction. |
| High churn on specific table | Tune per-table autovacuum parameters. |
| Instance resource pressure | Scale the instance or reduce load. |
| Bloat already severe | Run manual `VACUUM FULL` or `pg_repack` during maintenance window. |
| Statistics stale | Run manual `ANALYZE` on affected tables. |

### Manual vacuum/analyze

```sql
-- Safe to run anytime, but may hold locks
VACUUM (ANALYZE) public.<table>;

-- Full vacuum reclaims space but locks exclusively
VACUUM FULL public.<table>;
```

> **Warning:** `VACUUM FULL` requires an exclusive lock and rewrites the entire table. Schedule during a maintenance window.

### Per-table autovacuum tuning

```sql
-- More aggressive vacuum for high-churn tables
ALTER TABLE public.<table> SET (
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_analyze_scale_factor = 0.05,
  autovacuum_vacuum_threshold = 1000,
  autovacuum_analyze_threshold = 1000
);
```

## Verify

- All `database_maintenance_bloat_ratio` < 0.1 for 15 minutes.
- All `database_maintenance_last_vacuum_age_seconds` < 86,400.
- All `database_maintenance_last_analyze_age_seconds` < 86,400.
- All `database_maintenance_dead_tuples` < 10,000.
- `database_maintenance_status_total{status="ok"}` = 1.
- No readiness failures from `database_maintenance` probe.

## Escalate

- Bloat > 0.5 on critical tables (users, organizations, payments, proofs) — requires `VACUUM FULL` or `pg_repack`.
- Autovacuum cannot keep up despite tuning — instance may be undersized.
- Multiple tables with critical dead tuples and overdue vacuum — investigate autovacuum configuration globally.
- Readiness failures persist after manual vacuum — investigate blocking transactions or locks.