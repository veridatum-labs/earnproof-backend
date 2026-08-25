# feat(api): add recurring-income proofs

Closes #7

## Summary

Adds the `RECURRING_INCOME` proof type to the issuance, signing, revocation, and
public verification lifecycle. No new lifecycle infrastructure is introduced — the
new proof type plugs directly into the existing paths.

## Changes

| File | Description |
|---|---|
| `src/proofs/dto/create-recurring-income-proof.dto.ts` | New request DTO |
| `src/proofs/proofs.service.ts` | New proof method, credential type, and helpers |
| `src/proofs/proofs.controller.ts` | New `POST /proofs/recurring-income` endpoint |
| `src/proofs/proofs.service.spec.ts` | 13 new unit tests |
| `src/proofs/proofs.lifecycle.spec.ts` | Full lifecycle test (create → verify → revoke → re-verify) |

No schema migration is required. `ProofType.RECURRING_INCOME` and
`ProofClaim.frequency` were already present in `prisma/schema.prisma`.

---

## Design

### Interval evaluation

`createRecurringIncomeProof` accepts `intervalUnit` (`day` | `week` | `month`) and
`intervalCount` (2–120). It splits `[periodStart, periodEnd]` into `intervalCount`
equal sub-intervals and checks that every interval contains at least one qualifying
payment.

If any interval is empty the method throws `BadRequestException` with an explicit
**"unsatisfied"** message. A credential is never issued for a partial cadence — there
is no partial or misleading result path.

Month boundaries are calendar-month-aware (UTC). Week and day intervals are
fixed-length.

### Claim schema and versioning

New credential shape:

```json
{
  "id": "<uuid>",
  "type": "EarnProofRecurringIncomeCredential",
  "schemaVersion": "earnproof.recurring-income.v1",
  "issuer": "earnproof-backend",
  "subject": { "walletHash": "sha256:..." },
  "claim": {
    "cadence": "month:3",
    "intervalUnit": "month",
    "intervalCount": 3,
    "assetCode": "XLM",
    "assetIssuer": null,
    "periodStart": "2026-04-01T00:00:00.000Z",
    "periodEnd": "2026-06-30T23:59:59.000Z",
    "qualifyingPaymentCount": 3
  },
  "privacy": {
    "exactIncomeHidden": true,
    "sourceTransactionsHidden": true
  },
  "issuedAt": "...",
  "expiresAt": "..."
}
```

`schemaVersion: "earnproof.recurring-income.v1"` and
`type: "EarnProofRecurringIncomeCredential"` are distinct from the minimum-income
values, so verifiers can tell the two claim shapes apart unambiguously.

`ProofClaim.frequency` stores the cadence string (`"unit:count"`, e.g. `"month:3"`).
`ProofClaim.operator` is set to `"recurring"`.

### Disclosure boundary

The signed credential discloses only: cadence, period, asset, interval count, and
qualifying payment count. It does **not** disclose:

- Source payment IDs
- Exact aggregate income or per-payment amounts
- Per-interval payment breakdown

Enforced by the `privacy: { exactIncomeHidden: true, sourceTransactionsHidden: true }`
envelope and verified in the test suite by serializing the full response and asserting
absence of raw amounts and payment IDs.

### Lifecycle integration

| Lifecycle step | How it integrates |
|---|---|
| **Revocation** | `revokeProof` is proof-type agnostic — no changes required |
| **Contract anchoring** | Same `anchorProof` / `revokeProof` calls as minimum-income |
| **Public verification** | `verifyProof` dispatches to a new `rebuildAndSign` private method that branches on `proofType`, calling the correct credential builder so the hash recomputed at verification time matches the hash stored at issuance time |
| **Verification events** | Written identically for all proof types |

---

## Trade-offs

- **Minimum `intervalCount` is 2.** A single-interval cadence proof is semantically
  equivalent to a payment-receipt, so `min: 2` is enforced in the DTO. Relaxing this
  is a one-line DTO change if needed.

- **No per-interval minimum amount threshold.** The proof attests to cadence
  (presence of at least one qualifying payment per interval), not to a per-interval
  income floor. Adding a per-interval threshold would require a new claim field and
  disclosure policy entry — a backwards-compatible extension that is out of scope for
  this issue.

- **Calendar-month intervals are variable-length.** `month` boundaries are
  calendar-month-aware (UTC `setUTCMonth`), so interval lengths vary between 28 and
  31 days. This matches the natural meaning of "monthly income" but means two
  `month:3` proofs covering different quarters have intervals of different absolute
  lengths. `week` and `day` intervals are fixed-length.

---

## Tests

### Unit tests (`proofs.service.spec.ts`)

| # | Scenario |
|---|---|
| 1 | Complete cadence (all intervals satisfied) issues a valid proof |
| 2 | Privacy boundary — source transactions and exact amounts absent from output |
| 3 | Missing interval produces the unsatisfied error, not a credential |
| 4 | Boundary timestamps (payment exactly at interval start / period end edge) |
| 5 | Wrong payment classification rejected |
| 6 | Mixed assets rejected |
| 7 | Ownership scoping — payments not owned by requester excluded |
| 8 | HMAC-SHA256 signature on the resulting credential |
| 9 | Revocation of a recurring-income proof |
| 10 | Public verification returns VALID with correct cadence claim |
| 11 | Tampered credential returns INVALID_SIGNATURE |
| 12 | Revoked proof returns REVOKED on verification |
| 13 | Schema version is distinct from minimum-income |

### Lifecycle test (`proofs.lifecycle.spec.ts`)

End-to-end in-memory store: create → verify (VALID) → revoke → re-verify (REVOKED),
covering the full `ProofsService` lifecycle for the recurring-income proof type.

---

## Validation commands

```
npm run lint
npm run test -- --runInBand
npm run build
```
