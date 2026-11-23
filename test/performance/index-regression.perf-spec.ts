import {
  performanceDatabaseAvailable,
  performanceDatabase,
} from "./harness/client";
import { explainQuery } from "./harness/explain";

/**
 * Database index usage regression checks (#432).
 *
 * Scope: High-value list, lookup, cleanup, and worker queries.
 *
 * Cardinality Assumptions:
 * - Representative datasets with scale > 5,000 - 50,000 rows seeded (see scale-seed.ts).
 * - Under production cardinality, the query planner chooses B-Tree / Unique index scans
 *   over full relation sequential scans.
 *
 * Normalization:
 * - Plans are normalized to node types and index names to avoid flaky environment-specific
 *   timing noise while preserving actionable regression tripwires.
 */

describe("Database Index Usage Regression Suite", () => {
  let skip = false;

  beforeAll(async () => {
    skip = !(await performanceDatabaseAvailable());
    if (skip) {
      console.warn(
        "Skipping index-regression.perf-spec.ts: TEST_DATABASE_URL is not set or " +
          "PostgreSQL is unreachable.",
      );
    }
  });

  describe("1. High-Value Lookup Queries", () => {
    it("AuthSession: tokenHash unique index lookup avoids sequential scan", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT * FROM "AuthSession" WHERE "tokenHash" = $1 LIMIT 1`,
        ["synthetic_token_hash_lookup_sample_12345"],
      );

      expect(summary.seqScannedRelations.has("AuthSession")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /tokenhash/i.test(idx) || /authsession/i.test(idx)),
      ).toBe(true);
    });

    it("Proof: credentialHash unique index lookup avoids sequential scan", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT * FROM "Proof" WHERE "credentialHash" = $1 LIMIT 1`,
        ["synthetic_credential_hash_sample_67890"],
      );

      expect(summary.seqScannedRelations.has("Proof")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /credentialhash/i.test(idx) || /proof/i.test(idx)),
      ).toBe(true);
    });
  });

  describe("2. High-Value List Queries", () => {
    it("Payment: tenant filtered history uses (userId, occurredAt) composite index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id", "userId", "occurredAt", "assetCode", "classification"
           FROM "Payment"
          WHERE "userId" = $1
          ORDER BY "occurredAt" DESC
          LIMIT 100`,
        ["synthetic_perf_heavy_user_0"],
      );

      expect(summary.seqScannedRelations.has("Payment")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /userid/i.test(idx) || /occurredat/i.test(idx)),
      ).toBe(true);
    });

    it("OrganizationMember: lookup by organizationId uses index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id", "organizationId", "userId", "role", "status"
           FROM "OrganizationMember"
          WHERE "organizationId" = $1 AND "status" = 'ACTIVE'
          LIMIT 50`,
        ["synthetic_org_id_123"],
      );

      expect(summary.seqScannedRelations.has("OrganizationMember")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /organizationid/i.test(idx) || /org/i.test(idx)),
      ).toBe(true);
    });
  });

  describe("3. Worker & Sweep Queries", () => {
    it("WebhookDelivery: worker retry queue sweep uses (status, nextRetryAt) index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id", "webhookId", "attempt", "nextRetryAt"
           FROM "WebhookDelivery"
          WHERE "status" = 'PENDING' AND "nextRetryAt" <= now()
          ORDER BY "nextRetryAt" ASC
          LIMIT 100`,
      );

      expect(summary.seqScannedRelations.has("WebhookDelivery")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /status/i.test(idx) || /nextretryat/i.test(idx)),
      ).toBe(true);
    });

    it("AnchorIntent: background anchoring worker pending queries use status index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id", "status", "createdAt"
           FROM "AnchorIntent"
          WHERE "status" = 'PENDING'
          ORDER BY "createdAt" ASC
          LIMIT 50`,
      );

      expect(summary.seqScannedRelations.has("AnchorIntent")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /status/i.test(idx) || /anchorintent/i.test(idx)),
      ).toBe(true);
    });
  });

  describe("4. Cleanup & Eviction Queries", () => {
    it("WalletChallenge: expired challenge cleanup uses expiresAt index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id" FROM "WalletChallenge" WHERE "expiresAt" < now() LIMIT 200`,
      );

      expect(summary.seqScannedRelations.has("WalletChallenge")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /expiresat/i.test(idx)),
      ).toBe(true);
    });

    it("AuthSession: expired session eviction sweep uses expiresAt index", async () => {
      if (skip) return;
      const db = performanceDatabase();

      const summary = await explainQuery(
        db.prisma,
        `SELECT "id" FROM "AuthSession" WHERE "expiresAt" < now() LIMIT 200`,
      );

      expect(summary.seqScannedRelations.has("AuthSession")).toBe(false);
      expect(
        [...summary.indexesUsed].some((idx) => /expiresat/i.test(idx)),
      ).toBe(true);
    });
  });
});
