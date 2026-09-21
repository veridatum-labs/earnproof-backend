import {
  AGGREGATE_EARNINGS_MAX_PERIOD_DAYS,
  AGGREGATE_EARNINGS_MAX_SOURCES,
  AGGREGATE_EARNINGS_POLICY_VERSION,
  AggregateEarningsPolicyError,
  aggregateEligibleEarnings,
  dedupeAggregateComponents,
  formatStroops,
  normalizeAmountToStroops,
  type AggregateEarningsComponent,
} from "./aggregate-earnings.policy";

const PERIOD_START = new Date("2025-01-01T00:00:00.000Z");
const PERIOD_END = new Date("2025-12-31T23:59:59.000Z");
const ASSET_CODE = "USDC";
const ASSET_ISSUER = "GISSUER";

function component(
  overrides: Partial<AggregateEarningsComponent> = {},
): AggregateEarningsComponent {
  return {
    paymentId: "payment_1",
    operationId: "op_1",
    sourceAddress: "GSOURCE_1",
    assetCode: ASSET_CODE,
    assetIssuer: ASSET_ISSUER,
    amount: "10.0000000",
    classification: "INCOME",
    isEligible: true,
    occurredAt: new Date("2025-06-01T00:00:00.000Z"),
    ...overrides,
  };
}

function options(overrides: Record<string, unknown> = {}) {
  return {
    periodStart: PERIOD_START,
    periodEnd: PERIOD_END,
    assetCode: ASSET_CODE,
    assetIssuer: ASSET_ISSUER,
    ...overrides,
  };
}

/** Small deterministic PRNG so property cases are reproducible. */
function mulberry32(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle<T>(items: readonly T[], random: () => number): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

function errorCode(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    return error instanceof AggregateEarningsPolicyError
      ? error.code
      : (error as Error).name;
  }
}

describe("aggregate-earnings policy — normalization and rounding", () => {
  it.each([
    ["0", 0n],
    ["1", 10_000_000n],
    ["1.5", 15_000_000n],
    ["1.1234567", 11_234_567n],
    ["000100.0000000", 1_000_000_000n],
    ["0.0000001", 1n],
  ])("normalizes %s to exact stroops", (amount, expected) => {
    expect(normalizeAmountToStroops(amount)).toBe(expected);
  });

  it("rounds the 8th decimal half-up rather than truncating", () => {
    expect(normalizeAmountToStroops("1.12345674")).toBe(11_234_567n);
    expect(normalizeAmountToStroops("1.12345675")).toBe(11_234_568n);
    expect(normalizeAmountToStroops("0.00000004")).toBe(0n);
    expect(normalizeAmountToStroops("0.00000005")).toBe(1n);
    expect(normalizeAmountToStroops("1.99999995")).toBe(20_000_000n);
  });

  it("round-trips every 7-decimal value exactly", () => {
    const random = mulberry32(20260101);
    for (let i = 0; i < 500; i += 1) {
      const whole = Math.floor(random() * 1_000_000);
      const fraction = Math.floor(random() * 10_000_000)
        .toString()
        .padStart(7, "0");
      const amount = `${whole}.${fraction}`;
      expect(formatStroops(normalizeAmountToStroops(amount))).toBe(amount);
    }
  });

  it.each([
    ["-1"],
    ["abc"],
    ["1.2.3"],
    [""],
    ["1,5"],
    [" 1 "],
    ["1e3"],
    [".5"],
  ])("rejects malformed amount %s", (amount) => {
    expect(errorCode(() => normalizeAmountToStroops(amount))).toBe(
      "AMOUNT_INVALID",
    );
  });
});

describe("aggregate-earnings policy — period bounds", () => {
  it("accepts a period exactly at the inclusive maximum span", () => {
    const start = new Date("2025-01-01T00:00:00.000Z");
    const end = new Date(
      start.getTime() + AGGREGATE_EARNINGS_MAX_PERIOD_DAYS * 24 * 60 * 60 * 1000,
    );
    expect(
      errorCode(() =>
        aggregateEligibleEarnings([component({ occurredAt: start })], {
          ...options({ periodStart: start, periodEnd: end }),
        }),
      ),
    ).toBeUndefined();
  });

  it("rejects a period one millisecond beyond the maximum span", () => {
    const start = new Date("2025-01-01T00:00:00.000Z");
    const end = new Date(
      start.getTime() +
        AGGREGATE_EARNINGS_MAX_PERIOD_DAYS * 24 * 60 * 60 * 1000 +
        1,
    );
    expect(
      errorCode(() =>
        aggregateEligibleEarnings([component({ occurredAt: start })], {
          ...options({ periodStart: start, periodEnd: end }),
        }),
      ),
    ).toBe("PERIOD_TOO_LONG");
  });

  it("rejects an inverted period", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings([component()], {
          ...options({ periodStart: PERIOD_END, periodEnd: PERIOD_START }),
        }),
      ),
    ).toBe("PERIOD_INVALID");
  });

  it("treats both period boundaries as inclusive", () => {
    const startEdge = aggregateEligibleEarnings(
      [component({ occurredAt: PERIOD_START })],
      options(),
    );
    const endEdge = aggregateEligibleEarnings(
      [component({ occurredAt: PERIOD_END })],
      options(),
    );
    expect(startEdge.totalAmount).toBe("10.0000000");
    expect(endEdge.totalAmount).toBe("10.0000000");
  });

  it("rejects a component one millisecond outside the period", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [
            component({
              occurredAt: new Date(PERIOD_START.getTime() - 1),
            }),
          ],
          options(),
        ),
      ),
    ).toBe("COMPONENT_OUTSIDE_PERIOD");

    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [component({ occurredAt: new Date(PERIOD_END.getTime() + 1) })],
          options(),
        ),
      ),
    ).toBe("COMPONENT_OUTSIDE_PERIOD");
  });
});

describe("aggregate-earnings policy — determinism", () => {
  it("is independent of component order for any shuffled input", () => {
    const random = mulberry32(424242);
    const components = Array.from({ length: 40 }, (_, index) =>
      component({
        paymentId: `payment_${index}`,
        operationId: `op_${index.toString().padStart(3, "0")}`,
        sourceAddress: `GSOURCE_${index % 5}`,
        amount: `${index}.${index.toString().padStart(7, "0")}`,
      }),
    );

    const baseline = aggregateEligibleEarnings(components, options());
    const expectedTotal = components.reduce(
      (sum, item) => sum + normalizeAmountToStroops(item.amount),
      0n,
    );
    expect(baseline.totalStroops).toBe(expectedTotal);

    for (let iteration = 0; iteration < 25; iteration += 1) {
      const result = aggregateEligibleEarnings(
        shuffle(components, random),
        options(),
      );
      expect(result).toEqual(baseline);
    }
  });

  it("derives the total from exact integer arithmetic, not floating point", () => {
    const result = aggregateEligibleEarnings(
      [
        component({ paymentId: "a", operationId: "a", amount: "0.1" }),
        component({ paymentId: "b", operationId: "b", amount: "0.2" }),
      ],
      options(),
    );
    expect(result.totalAmount).toBe("0.3000000");
  });
});

describe("aggregate-earnings policy — duplicate payments", () => {
  it("counts an operation once even when presented under two payment rows", () => {
    const result = aggregateEligibleEarnings(
      [
        component({
          paymentId: "payment_a",
          operationId: "shared-operation",
          amount: "100.0000000",
        }),
        component({
          paymentId: "payment_b",
          operationId: "shared-operation",
          amount: "100.0000000",
        }),
      ],
      options(),
    );

    expect(result.qualifyingPaymentCount).toBe(1);
    expect(result.totalAmount).toBe("100.0000000");
  });

  it("keeps the same survivor regardless of input order", () => {
    const rows = [
      component({ paymentId: "z", operationId: "dup", amount: "1.0000000" }),
      component({ paymentId: "a", operationId: "dup", amount: "1.0000000" }),
      component({ paymentId: "m", operationId: "dup", amount: "1.0000000" }),
    ];

    expect(dedupeAggregateComponents(rows)[0]?.paymentId).toBe("a");
    expect(dedupeAggregateComponents([...rows].reverse())[0]?.paymentId).toBe(
      "a",
    );
  });
});

describe("aggregate-earnings policy — asset rules", () => {
  it("accepts a single matching asset", () => {
    expect(
      aggregateEligibleEarnings([component()], options()).totalAmount,
    ).toBe("10.0000000");
  });

  it("rejects a component on a different asset than requested", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [component({ assetCode: "XLM", assetIssuer: null })],
          options(),
        ),
      ),
    ).toBe("ASSET_MISMATCH");
  });

  it("rejects cross-asset aggregation when no conversion policy is named", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [
            component(),
            component({
              paymentId: "payment_2",
              operationId: "op_2",
              assetCode: "XLM",
              assetIssuer: null,
            }),
          ],
          options(),
        ),
      ),
    ).toBe("CROSS_ASSET_UNSUPPORTED");
  });

  it("rejects a named conversion policy that is not registered", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [
            component(),
            component({
              paymentId: "payment_2",
              operationId: "op_2",
              assetCode: "XLM",
              assetIssuer: null,
            }),
          ],
          options({ conversionPolicy: "oracle-spot/v1" }),
        ),
      ),
    ).toBe("CONVERSION_POLICY_UNSUPPORTED");
  });
});

describe("aggregate-earnings policy — eligibility and source bounds", () => {
  it("rejects a non-income component", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [component({ classification: "REIMBURSEMENT" })],
          options(),
        ),
      ),
    ).toBe("INELIGIBLE_COMPONENT");
  });

  it("rejects an income component that is not eligible", () => {
    expect(
      errorCode(() =>
        aggregateEligibleEarnings(
          [component({ isEligible: false })],
          options(),
        ),
      ),
    ).toBe("INELIGIBLE_COMPONENT");
  });

  it("rejects an empty selection", () => {
    expect(errorCode(() => aggregateEligibleEarnings([], options()))).toBe(
      "NO_ELIGIBLE_COMPONENTS",
    );
  });

  it("bounds the number of distinct sources", () => {
    const atLimit = Array.from(
      { length: AGGREGATE_EARNINGS_MAX_SOURCES },
      (_, index) =>
        component({
          paymentId: `payment_${index}`,
          operationId: `op_${index}`,
          sourceAddress: `GSOURCE_${index}`,
          amount: "1.0000000",
        }),
    );
    expect(
      aggregateEligibleEarnings(atLimit, options()).sourceCount,
    ).toBe(AGGREGATE_EARNINGS_MAX_SOURCES);

    const oneTooMany = [
      ...atLimit,
      component({
        paymentId: "payment_extra",
        operationId: "op_extra",
        sourceAddress: "GSOURCE_EXTRA",
      }),
    ];
    expect(
      errorCode(() => aggregateEligibleEarnings(oneTooMany, options())),
    ).toBe("TOO_MANY_SOURCES");
  });

  it("exposes the committed policy version", () => {
    expect(AGGREGATE_EARNINGS_POLICY_VERSION).toBe(
      "aggregate-earnings-policy.v1",
    );
  });
});
