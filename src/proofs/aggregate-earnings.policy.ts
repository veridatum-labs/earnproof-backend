/**
 * Bounded aggregation policy for `AGGREGATE_EARNINGS` proofs.
 *
 * `AGGREGATE_EARNINGS` exists in the `ProofType` enum but, before this policy,
 * nothing defined *which* payments may be summed, over what period, at what
 * precision, or what happens when the selection spans more than one asset. A
 * proof type without that contract is not safe to issue: two servers could
 * legitimately disagree on the same inputs, an unbounded selection could turn a
 * single request into an unbounded decrypt-and-sum loop, and mixed-asset
 * selections could be silently added together as though every asset were worth
 * the same.
 *
 * This module is the whole contract, as pure functions with no database or
 * configuration dependency, so it can be property-tested directly:
 *
 * - Eligible components: classified `INCOME`, marked eligible, and inside the
 *   requested period. Anything else is rejected rather than quietly skipped —
 *   a caller asking for an ineligible payment has a bug; hiding it would let
 *   the resulting total look authoritative while being wrong.
 * - Period bounds: `periodStart <= periodEnd` and an inclusive span of at most
 *   {@link AGGREGATE_EARNINGS_MAX_PERIOD_DAYS} days. "All of history" is not a
 *   period; it is an unbounded scan with no meaningful claim.
 * - Normalization: every amount is read as a decimal string and rounded
 *   half-up to Stellar's 7-decimal precision (1 stroop = 1e-7). Summing
 *   floating point numbers is forbidden because `0.1 + 0.2 !== 0.3`; the sum
 *   is exact integer arithmetic in stroops.
 * - Duplicate payments: components are deduplicated by `operationId` before
 *   anything is counted, so the same on-chain operation cannot contribute
 *   twice even if it is presented twice.
 * - Determinism: the deduplicated set is sorted by `operationId` (then
 *   `paymentId`) before summing, so the result does not depend on database row
 *   order.
 * - Cross-asset aggregation: rejected unless the caller names an explicit
 *   conversion policy. No conversion policy is registered today, so mixed
 *   assets fail closed. Should one be added, it is added to
 *   {@link SUPPORTED_CONVERSION_POLICIES} and the `conversionPolicy` field
 *   starts being honored.
 */

/** Credential schema version committed for every aggregate-earnings proof. */
export const AGGREGATE_EARNINGS_SCHEMA_VERSION =
  "earnproof.aggregate-earnings.v1";

/**
 * Version of the aggregation rules themselves.
 *
 * Committed into the credential and the stored disclosure policy so a verifier
 * can tell which rounding, deduplication, and eligibility rules produced a
 * total. Changing any rule in this module requires a new version; existing
 * credentials keep the version they were issued under.
 */
export const AGGREGATE_EARNINGS_POLICY_VERSION =
  "aggregate-earnings-policy.v1";

/** Inclusive maximum span of a single aggregation period. */
export const AGGREGATE_EARNINGS_MAX_PERIOD_DAYS = 366;

/** Maximum distinct payment sources (payer addresses) in one aggregate. */
export const AGGREGATE_EARNINGS_MAX_SOURCES = 100;

/** Decimal places Stellar amounts are exact to. */
export const AGGREGATE_EARNINGS_SCALE = 7;

const SCALE_FACTOR = 10n ** BigInt(AGGREGATE_EARNINGS_SCALE);
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const AMOUNT_PATTERN = /^(\d+)(?:\.(\d+))?$/;

/**
 * Conversion policy names the issuer understands today.
 *
 * Empty on purpose: converting between assets requires a rate source, a
 * quotation time, and a disclosure decision about the rate used. None of that
 * exists yet, so naming a policy cannot make a mixed-asset total meaningful.
 * The list is the single place a future implementation registers itself.
 */
export const SUPPORTED_CONVERSION_POLICIES: readonly string[] = [];

export type AggregateEarningsPolicyCode =
  | "PERIOD_INVALID"
  | "PERIOD_TOO_LONG"
  | "AMOUNT_INVALID"
  | "NO_ELIGIBLE_COMPONENTS"
  | "INELIGIBLE_COMPONENT"
  | "COMPONENT_OUTSIDE_PERIOD"
  | "ASSET_MISMATCH"
  | "CROSS_ASSET_UNSUPPORTED"
  | "CONVERSION_POLICY_UNSUPPORTED"
  | "TOO_MANY_SOURCES";

/** A policy violation, carrying a stable code for callers and tests. */
export class AggregateEarningsPolicyError extends Error {
  constructor(
    readonly code: AggregateEarningsPolicyCode,
    message: string,
  ) {
    super(message);
    this.name = "AggregateEarningsPolicyError";
  }
}

/** Canonical identity of an asset: code plus issuer, or `native` for XLM. */
export function assetKey(code: string, issuer: string | null): string {
  return `${code}:${issuer ?? "native"}`;
}

/**
 * Validates a period against the aggregation bounds.
 *
 * `periodEnd` is inclusive, and the span is measured as elapsed time, so a
 * period that starts and ends at midnight 366 days apart is accepted while one
 * seven minutes longer is refused.
 */
export function assertAggregatePeriod(start: Date, end: Date): void {
  if (
    Number.isNaN(start.getTime()) ||
    Number.isNaN(end.getTime()) ||
    start > end
  ) {
    throw new AggregateEarningsPolicyError(
      "PERIOD_INVALID",
      "periodStart must be on or before periodEnd",
    );
  }

  const spanMs = end.getTime() - start.getTime();
  if (spanMs > AGGREGATE_EARNINGS_MAX_PERIOD_DAYS * MS_PER_DAY) {
    throw new AggregateEarningsPolicyError(
      "PERIOD_TOO_LONG",
      `Aggregation period may not exceed ${AGGREGATE_EARNINGS_MAX_PERIOD_DAYS} days`,
    );
  }
}

/** True when `occurredAt` falls inside the inclusive period. */
export function isWithinAggregatePeriod(
  occurredAt: Date,
  start: Date,
  end: Date,
): boolean {
  return occurredAt >= start && occurredAt <= end;
}

/**
 * Parses a non-negative decimal amount and rounds it half-up to 7 decimals,
 * returning exact stroops.
 *
 * Extra precision is rounded rather than truncated: 1.23456785 becomes
 * 1.2345679, not 1.2345678, so the aggregate does not systematically
 * understate. Values with no fractional part are accepted, as is a trailing
 * run of zeros.
 */
export function normalizeAmountToStroops(amount: string): bigint {
  const match = AMOUNT_PATTERN.exec(amount);
  if (!match) {
    throw new AggregateEarningsPolicyError(
      "AMOUNT_INVALID",
      `Amount "${amount}" is not a non-negative decimal string`,
    );
  }

  const whole = BigInt(match[1]);
  const fraction = match[2] ?? "";
  const keptFraction = fraction.slice(0, AGGREGATE_EARNINGS_SCALE);
  const stroops =
    whole * SCALE_FACTOR +
    BigInt(keptFraction.padEnd(AGGREGATE_EARNINGS_SCALE, "0"));

  const roundingDigit =
    fraction.length > AGGREGATE_EARNINGS_SCALE
      ? fraction.charCodeAt(AGGREGATE_EARNINGS_SCALE) - 48
      : 0;

  return roundingDigit >= 5 ? stroops + 1n : stroops;
}

/** Renders exact stroops as a fixed 7-decimal string. */
export function formatStroops(stroops: bigint): string {
  if (stroops < 0n) {
    throw new AggregateEarningsPolicyError(
      "AMOUNT_INVALID",
      "Aggregate earnings cannot be negative",
    );
  }

  const whole = stroops / SCALE_FACTOR;
  const fraction = (stroops % SCALE_FACTOR)
    .toString()
    .padStart(AGGREGATE_EARNINGS_SCALE, "0");
  return `${whole}.${fraction}`;
}

/**
 * Stable ordering for aggregation components.
 *
 * `operationId` is the on-chain identity of a payment and the schema's unique
 * key, so it is the primary sort key; `paymentId` breaks ties deterministically
 * when a caller supplies the same operation under more than one row.
 */
export function sortAggregateComponents<
  T extends { operationId: string; paymentId: string },
>(components: readonly T[]): T[] {
  return [...components].sort((left, right) => {
    if (left.operationId !== right.operationId) {
      return left.operationId < right.operationId ? -1 : 1;
    }
    if (left.paymentId !== right.paymentId) {
      return left.paymentId < right.paymentId ? -1 : 1;
    }
    return 0;
  });
}

/**
 * Collapses components to one row per `operationId`, keeping the
 * lexicographically smallest `paymentId` for each. The order of the input
 * never changes which row survives.
 */
export function dedupeAggregateComponents<
  T extends { operationId: string; paymentId: string },
>(components: readonly T[]): T[] {
  const seen = new Set<string>();
  const deduped: T[] = [];

  for (const component of sortAggregateComponents(components)) {
    if (seen.has(component.operationId)) continue;
    seen.add(component.operationId);
    deduped.push(component);
  }

  return deduped;
}

/** One eligible-payment candidate considered by the policy. */
export interface AggregateEarningsComponent {
  paymentId: string;
  operationId: string;
  sourceAddress: string;
  assetCode: string;
  assetIssuer: string | null;
  /** Plaintext decimal amount. */
  amount: string;
  classification: string;
  isEligible: boolean;
  occurredAt: Date;
}

export interface AggregateEarningsOptions {
  periodStart: Date;
  periodEnd: Date;
  assetCode: string;
  assetIssuer: string | null;
  conversionPolicy?: string;
}

export interface AggregateEarningsResult {
  totalStroops: bigint;
  /** Total rendered at 7 decimals, e.g. `"123.4000000"`. */
  totalAmount: string;
  /** Number of distinct eligible payments counted. */
  qualifyingPaymentCount: number;
  /** Number of distinct payer addresses contributing. */
  sourceCount: number;
}

function assertAssetPolicy(
  distinctAssets: ReadonlySet<string>,
  expectedAsset: string,
  conversionPolicy?: string,
): void {
  if (
    conversionPolicy !== undefined &&
    !SUPPORTED_CONVERSION_POLICIES.includes(conversionPolicy)
  ) {
    throw new AggregateEarningsPolicyError(
      "CONVERSION_POLICY_UNSUPPORTED",
      `Conversion policy "${conversionPolicy}" is not supported`,
    );
  }

  if (distinctAssets.size > 1) {
    throw new AggregateEarningsPolicyError(
      "CROSS_ASSET_UNSUPPORTED",
      "Cross-asset aggregation requires an explicit conversion policy; none is configured",
    );
  }

  const [onlyAsset] = distinctAssets;
  if (onlyAsset !== undefined && onlyAsset !== expectedAsset) {
    throw new AggregateEarningsPolicyError(
      "ASSET_MISMATCH",
      "Selected payments must use the requested asset",
    );
  }
}

/**
 * Applies the whole policy to a set of candidate payments.
 *
 * The function is order-independent: shuffling `components` produces the same
 * `totalAmount`, `qualifyingPaymentCount`, and `sourceCount`.
 */
export function aggregateEligibleEarnings(
  components: readonly AggregateEarningsComponent[],
  options: AggregateEarningsOptions,
): AggregateEarningsResult {
  assertAggregatePeriod(options.periodStart, options.periodEnd);

  const deduped = dedupeAggregateComponents(components);
  if (deduped.length === 0) {
    throw new AggregateEarningsPolicyError(
      "NO_ELIGIBLE_COMPONENTS",
      "At least one eligible payment is required",
    );
  }

  const expectedAsset = assetKey(options.assetCode, options.assetIssuer);
  const distinctAssets = new Set<string>();
  const sources = new Set<string>();
  let totalStroops = 0n;

  for (const component of deduped) {
    if (component.classification !== "INCOME" || !component.isEligible) {
      throw new AggregateEarningsPolicyError(
        "INELIGIBLE_COMPONENT",
        `Payment ${component.paymentId} is not an eligible income payment`,
      );
    }

    if (
      !isWithinAggregatePeriod(
        component.occurredAt,
        options.periodStart,
        options.periodEnd,
      )
    ) {
      throw new AggregateEarningsPolicyError(
        "COMPONENT_OUTSIDE_PERIOD",
        `Payment ${component.paymentId} falls outside the aggregation period`,
      );
    }

    distinctAssets.add(assetKey(component.assetCode, component.assetIssuer));
    sources.add(component.sourceAddress);
    totalStroops += normalizeAmountToStroops(component.amount);
  }

  assertAssetPolicy(
    distinctAssets,
    expectedAsset,
    options.conversionPolicy,
  );

  if (sources.size > AGGREGATE_EARNINGS_MAX_SOURCES) {
    throw new AggregateEarningsPolicyError(
      "TOO_MANY_SOURCES",
      `Aggregate earnings may span at most ${AGGREGATE_EARNINGS_MAX_SOURCES} distinct sources`,
    );
  }

  return {
    totalStroops,
    totalAmount: formatStroops(totalStroops),
    qualifyingPaymentCount: deduped.length,
    sourceCount: sources.size,
  };
}
