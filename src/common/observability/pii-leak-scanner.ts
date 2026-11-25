/**
 * Sentinel-based integration scanner for PII leakage.
 *
 * The redaction rules in `redaction.ts` mask known patterns, but they cannot
 * prove that a newly added field stays out of a rendered log line, an exception
 * message, or an HTTP error body. This module fills that gap for integration
 * tests: callers register the sentinel values a test has deliberately placed in
 * a request (wallet address, token, memo, signature, amount), then run every
 * rendered output path through `scanRenderedOutputForSentinels`.
 *
 * A finding reports *where* the leak was observed (`pathLabel`, `outputKind`)
 * and *what kind* of secret leaked (`category`), together with the safe
 * correlation identifier so operators can correlate the incident. The raw
 * sentinel value is never included in a finding, so a failing assertion or an
 * error report never echoes the secret it exists to catch.
 */

export type SentinelCategory = "WALLET" | "TOKEN" | "MEMO" | "SIGNATURE" | "AMOUNT";

export interface SentinelSpec {
  category: SentinelCategory;
  value: string;
}

export interface LeakFinding {
  /** Human label of the emitting path (e.g. `POST /api/payments`). */
  pathLabel: string;
  /** Kind of rendered output that was scanned. */
  outputKind: "STRUCTURED_LOG" | "PLAIN_TEXT_LOG" | "ERROR_RESPONSE";
  /** Category of sentinel found in the output. */
  category: SentinelCategory;
  /** Safe correlation identifier, never the secret itself. */
  correlationId?: string;
}

/**
 * Scans a rendered output (string or JSON-serializable payload) for any of the
 * supplied sentinel values.
 *
 * Returns one finding per sentinel detected. The finding excludes the sentinel
 * value entirely. Returns an empty array when nothing is found or the payload
 * is empty.
 */
export function scanRenderedOutputForSentinels(params: {
  pathLabel: string;
  outputKind: LeakFinding["outputKind"];
  payload: unknown;
  sentinels: readonly SentinelSpec[];
  correlationId?: string;
}): LeakFinding[] {
  const serialized =
    typeof params.payload === "string"
      ? params.payload
      : JSON.stringify(params.payload ?? "");

  if (!serialized) {
    return [];
  }

  const findings: LeakFinding[] = [];
  for (const sentinel of params.sentinels) {
    if (!sentinel.value) continue;
    if (serialized.includes(sentinel.value)) {
      findings.push({
        pathLabel: params.pathLabel,
        outputKind: params.outputKind,
        category: sentinel.category,
        correlationId: params.correlationId,
      });
    }
  }

  return findings;
}

/**
 * Builds the standard, privacy-safe error envelope for an HTTP error response.
 *
 * The envelope carries only a stable code, a generic message, and the request's
 * correlation identifier. Never include raw exception text, stack traces, or
 * user-supplied values here — run those through
 * `scanRenderedOutputForSentinels` before rendering if they originated from a
 * path that handled sentinel values.
 */
export function buildSafeErrorEnvelope(params: {
  statusCode: number;
  code: string;
  message: string;
  correlationId: string;
}): {
  statusCode: number;
  error: {
    code: string;
    message: string;
    correlationId: string;
  };
} {
  return {
    statusCode: params.statusCode,
    error: {
      code: params.code,
      message: params.message,
      correlationId: params.correlationId,
    },
  };
}
