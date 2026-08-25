# feat(api): add contract anchoring outbox

Closes #16

## What changed

Optional proof anchoring previously called the Stellar CLI synchronously on the HTTP request thread. A transient RPC failure or process crash left proof state ambiguous with no recovery path. This PR fixes that with a durable outbox pattern.

---

## Design

### Schema — `AnchoringIntent`

A new `AnchoringIntent` table acts as the outbox. One row is written per anchoring operation (`REGISTER` or `REVOKE`) **in the same `$transaction`** as the `Proof` or status update — before any external call is made. Fields stored: `transactionHash`, `ledger`, `attemptCount`, `lastAttemptAt`, `nextRetryAt`, `lastErrorSafe`, `permanentError`.

Two new enums added: `AnchoringOperation` (`REGISTER | REVOKE`) and `AnchoringStatus` (`PENDING | PROCESSING | CONFIRMED | FAILED`). No existing models were changed.

### Worker — `AnchoringWorkerService`

- Polls every 10 s via `@nestjs/schedule` `@Interval`. No Bull/Redis added — a polling worker achieves the durability goal without expanding the dependency surface. The `poll()` trigger is trivially swappable for a queue later.
- Claims a batch of `PENDING` intents atomically inside a `$transaction` (PENDING → PROCESSING) to prevent double-processing on multi-replica deployments.
- **Crash recovery:** any intent left in `PROCESSING` for more than 5 minutes is presumed orphaned and reset to `PENDING` on the next poll tick.
- **Retry backoff:** base 30 s, 2× multiplier per attempt, 1 h cap, 10 attempt maximum.
- **Permanent vs transient errors:** errors matching known-permanent patterns (e.g. `already registered`, `unauthorized`) or reaching `MAX_ATTEMPTS` are set to `FAILED, permanentError=true` and not retried. All other failures reschedule with backoff.
- **Idempotency:** before calling the CLI, the worker checks for an existing `CONFIRMED` intent with the same `(proofId, operation)`. If one exists, the current intent is marked confirmed without a CLI call. Handles duplicate delivery safely across process restarts.
- **Secret safety:** `lastErrorSafe` is sanitised before storage — strips Stellar secret key patterns (`S[A-Z2-7]{55}`) and `KEY=VALUE` env-var-like strings. No signing key or CLI credential appears in job payloads, DB fields, or log lines.

### Reconciler — `AnchoringReconcilerService`

Runs every 5 minutes. Queries proofs with a `contractTransactionHash` and calls `getProofStatus` to compare local vs on-chain state:

| Local status | On-chain state | Action |
|---|---|---|
| `ACTIVE` | `valid=true, revoked=false` | OK — no action |
| `ACTIVE` | `revoked=true` | **Auto-repair:** mark local `REVOKED` |
| `ACTIVE` | `valid=false, revoked=false` | **Flag manual:** create `FAILED` intent with `permanentError=true` for operator review |
| `REVOKED` | `revoked=true` | OK — no action |
| `REVOKED` | `revoked=false` | **Auto-repair:** re-enqueue a `REVOKE` intent |

Auto-repair cases are logged at `WARN`. Manual-attention cases are logged at `ERROR` and surfaced as a `FAILED` intent so operators can find them via standard tooling.

### API behavior

**Proof creation (`POST /proofs/minimum-income`):**
- The `AnchoringIntent` is written in the same transaction as the `Proof` row.
- The HTTP response returns **immediately** — it never waits for the Stellar CLI.
- Response `anchoring` field: `{ anchored: false, reason: "pending" }` while queued, `{ anchored: false, reason: "disabled" }` when anchoring is off.

**Verification (`GET /proofs/:id/verify`):**
- **Optional anchoring** (`CONTRACT_ANCHORING_REQUIRED=false`, default): returns `VALID` regardless of whether anchoring has completed. Callers can see `contractStatus` in the response once the worker confirms.
- **Required anchoring** (`CONTRACT_ANCHORING_REQUIRED=true`): returns `UNVERIFIED_ISSUER` until `contractTransactionHash` is set by the worker. The proof exists in the DB immediately, but is not verifiable until anchored.

**Revocation (`PATCH /proofs/:id/revoke`):**
- Local status update + `REVOKE` intent written atomically. Response returns immediately with `anchoring: { anchored: false, reason: "pending" }`.

---

## Trade-offs

- **Polling vs queue:** Using `@nestjs/schedule` instead of Bull/BullMQ avoids adding a Redis-backed queue dependency, which would expand scope. At current proof volumes the 10 s poll latency is negligible.
- **Required anchoring writes to DB before confirmation:** blocking the HTTP response until anchoring completes was the exact problem being fixed. The `UNVERIFIED_ISSUER` response from `verify` enforces the policy without re-introducing synchronous CLI calls.

---

## Tests added

- **Crash recovery:** stale `PROCESSING` intents are reset to `PENDING` on the next poll
- **Duplicate delivery / idempotency:** `CONFIRMED` and `FAILED` intents are no-ops; CLI is skipped when a confirmed record already exists for `(proofId, operation)`
- **Retry behavior:** transient failures reschedule with backoff and `permanentError=false`; permanent error patterns and `MAX_ATTEMPTS` set `permanentError=true` with no further retries
- **Secret safety:** Stellar secret key patterns and env-var credentials are redacted in `lastErrorSafe`
- **Required vs optional anchoring policy:** `verify` returns `UNVERIFIED_ISSUER` / `VALID` depending on config and `contractTransactionHash` presence
- **Reconciler:** all five local/on-chain state combinations tested, including duplicate-guard for re-enqueue and manual-review intents

---

## Validation

```
npm run lint
(no output — 0 errors)
```

```
npm run test -- --runInBand
Test Suites: 10 passed, 10 total
Tests:       47 passed, 47 total
Snapshots:   0 total
Time:        22.825 s
Ran all test suites.
```

```
npm run build
(prisma generate + nest build — no errors, no warnings)
```
