/**
 * Privacy-safe ETag and cache policy for public proof verification.
 *
 * Public verification clients need to refresh efficiently without caching a
 * stale status across revocation or expiry changes. The ETag is derived only
 * from public verification state — the proof id, the public status, and the
 * proof's last state transition timestamp — never from non-public metadata,
 * payment data, or operator notes.
 *
 * Revoked and expired proofs carry `no-store, must-revalidate` so they can
 * never be served from a stale cache; all other states use
 * `public, max-age=0, must-revalidate`, forcing clients to revalidate on
 * every refresh while still allowing a 304 when nothing changed.
 */

import crypto from "node:crypto";

export type PublicProofStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "NOT_FOUND";

export interface ProofVerificationView {
  proofId: string;
  status: PublicProofStatus;
  updatedAtIso: string;
}

/**
 * Maps the public verification status string produced by the verification
 * service to a public-facing proof status suitable for ETag derivation.
 *
 * `invalid` (a tampered credential) still identifies an existing proof, so it
 * is treated as `ACTIVE` for cache purposes: the proof exists, its public
 * state just failed cryptographic validation.
 */
export function publicProofStatus(status: string): PublicProofStatus {
  switch (status) {
    case "valid":
      return "ACTIVE";
    case "expired":
      return "EXPIRED";
    case "revoked":
      return "REVOKED";
    case "unknown":
      return "NOT_FOUND";
    default:
      return "ACTIVE";
  }
}

/**
 * Derives a weak ETag from public verification state.
 *
 * The hash is truncated to 24 hex characters: long enough to change on every
 * public status transition, short enough to remain a compact header value. The
 * `W/` prefix marks it as a weak validator, since two distinct byte-for-byte
 * credential serializations can legitimately share a status and timestamp.
 */
export function computeProofEtag(view: ProofVerificationView): string {
  const digest = crypto
    .createHash("sha256")
    .update(`${view.proofId}:${view.status}:${view.updatedAtIso}`, "utf8")
    .digest("hex")
    .slice(0, 24);
  return `W/"${digest}"`;
}

/**
 * Conservative cache directive for a verification response.
 *
 * Revoked, expired, and unknown proofs must never be served from a stale
 * cache: `no-store, must-revalidate`. Every other state revalidates on each
 * request but allows a 304 when the ETag matches.
 */
export function getProofCacheControl(status: PublicProofStatus): string {
  if (status === "REVOKED" || status === "EXPIRED" || status === "NOT_FOUND") {
    return "no-store, must-revalidate";
  }
  return "public, max-age=0, must-revalidate";
}

/**
 * Evaluates an `If-None-Match` request header against the current ETag.
 *
 * Malformed or unrecognized values never produce a false 304: they fall out as
 * non-matching so the caller returns the current 200/404 representation with a
 * fresh ETag. `*` matches any current representation. Both strong and weak
 * forms of the current tag are accepted.
 */
export function matchesIfNoneMatch(
  ifNoneMatchHeader: string | undefined,
  currentEtag: string,
): boolean {
  if (!ifNoneMatchHeader || typeof ifNoneMatchHeader !== "string") {
    return false;
  }

  const normalizedCurrent = currentEtag.replace(/^W\//, "").trim();

  const candidates = ifNoneMatchHeader
    .split(",")
    .map((part) => part.trim())
    .filter(
      (part) =>
        part === "*" ||
        /^W\/"[^"]+"$/.test(part) ||
        /^"[^"]+"$/.test(part),
    );

  return candidates.some((candidate) => {
    if (candidate === "*") return true;
    return candidate.replace(/^W\//, "").trim() === normalizedCurrent;
  });
}
