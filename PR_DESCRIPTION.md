# feat(api): add signed webhook delivery

Closes #15

## Summary

Adds signed webhook delivery infrastructure for proof lifecycle and verification events. Proof creators can subscribe to allowlisted event types (`proof.created`, `proof.revoked`, `proof.verified`) and receive HMAC-SHA256 signed POST requests at configurable HTTPS endpoints. Deliveries are retried with bounded exponential backoff, protected against SSRF, and never leak private proof inputs in payloads or audit logs.

## Design

### Event types and payloads

Three allowlisted event types are emitted automatically:

1. **`proof.created`** – triggered after proof is created and (optionally) anchored on-chain
   - Includes: `proofId`, `proofType`, `status`, `network`, `asset`, `period`, `expiresAt`, `credentialHash`, `contractTransactionHash` (if anchored), `issuedAt`
   - Excludes: source transactions, exact threshold/income amounts, private encryption keys

2. **`proof.revoked`** – triggered after proof status is set to REVOKED
   - Includes: `proofId`, `status`, `revokedAt`

3. **`proof.verified`** – triggered after a verification result is recorded
   - Includes: `proofId`, `result` (VALID/EXPIRED/REVOKED/INVALID/UNKNOWN), `verifiedAt`

Payloads are wrapped in a versioned envelope:
```json
{
  "specVersion": "1",
  "id": "<deliveryId>",
  "event": "<eventType>",
  "createdAt": "<ISO-8601>",
  "data": { ... }
}
```

### Signing scheme

**Algorithm:** HMAC-SHA256

**Signing base string:** `<unix-timestamp-seconds>.<deliveryId>.<raw-json-body>`

**Request headers:**
| Header | Value |
|--------|-------|
| `X-EarnProof-Timestamp` | Unix timestamp in seconds |
| `X-EarnProof-Delivery` | Delivery ID (idempotency key) |
| `X-EarnProof-Event` | Event type, e.g. `proof.created` |
| `X-EarnProof-Signature` | `v1=<hex-encoded-HMAC-SHA256>` |
| `Content-Type` | `application/json` |

**Integrator verification procedure:**
1. Read timestamp and delivery ID from headers
2. Reconstruct signing base string: `timestamp + "." + deliveryId + "." + body`
3. Compute `HMAC-SHA256(signingSecret, baseString)` and hex-encode
4. Prepend `v1=` and compare with signature header using constant-time comparison
5. (Optional) Reject if timestamp is >5 minutes old

### Retry and ordering

**Retry behavior:**
- Maximum 5 delivery attempts (1 initial + 4 retries)
- Exponential backoff: `1s, 2s, 4s, 8s` (2^(attempt-2) × 1000ms)
- SSRF blocks are permanent (no retry)
- Each retry attempt produces a new `WebhookDelivery` row (for auditability)

**Ordering guarantees:**
- All deliveries for the same webhook endpoint are serialized in FIFO order
- Implemented via per-webhook in-memory Promise chains
- Surviving service restarts: on startup, all PENDING deliveries are re-enqueued
- Idempotency: same `eventId` is used across all retry attempts and manual replays

### Endpoint management API

**Create webhook:**
```
POST /api/v1/webhooks
Authorization: Bearer <token>
{
  "url": "https://example.com/hooks",
  "events": ["proof.created", "proof.verified"]
}
```
Returns raw signing secret **once** (never retrievable again).

**List webhooks:**
```
GET /api/v1/webhooks
```

**Rotate secret:**
```
POST /api/v1/webhooks/{id}/rotate-secret
```
Returns new raw secret once.

**Update subscriptions:**
```
PATCH /api/v1/webhooks/{id}/events
{
  "events": ["proof.created"]
}
```

**Disable/enable/delete:**
```
PATCH /api/v1/webhooks/{id}/disable
PATCH /api/v1/webhooks/{id}/enable
DELETE /api/v1/webhooks/{id}
```

**View delivery records:**
```
GET /api/v1/webhooks/{id}/deliveries
```

**Manual replay (DEVELOPER/ADMIN only):**
```
POST /api/v1/webhooks/deliveries/{deliveryId}/replay
Authorization: Bearer <token>
```

### SSRF protection

Blocks delivery to:
- **Loopback:** 127.0.0.0/8, `::1`, `localhost`, `*.localhost`
- **Private (RFC-1918):** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Link-local:** 169.254.0.0/16, `fe80::/10`
- **Cloud metadata:** 169.254.169.254 (AWS/GCP/Azure), 100.100.100.200 (Alibaba)
- **Special-use:** 0.0.0.0/8, 240.0.0.0/4, 255.255.255.255
- **Non-HTTPS schemes:** all non-`https://` URLs blocked

**Redirect handling:** `redirect: "error"` in fetch prevents following 3xx responses, preventing open redirects to internal addresses.

**Note:** This is a syntactic/IP-range check only; it does not perform DNS resolution and thus does not protect against DNS-rebinding attacks. Network-layer egress filtering provides complementary defence.

### Redaction and observability

**Secrets never leak:**
- Signing secret is stored encrypted (AES-256-GCM, same key as payment amounts)
- Decrypted only at delivery execution time
- Never appears in `WebhookDelivery` rows or delivery logs
- Secret rotation re-encrypts the key; old signatures become invalid on next retry

**Response bodies bounded:**
- Truncated at 1,024 bytes + `"…[truncated]"` suffix
- Prevents unbounded log storage

**Delivery records track:**
- Event type, delivery ID (idempotency key), attempt number
- HTTP status code, response body (truncated), duration
- Retry schedule (next retry timestamp)
- SSRF/permanent failures captured in `failureReason`
- Manual replay origin (`replayOf`, `replayedBy`)

**Audit log on replay:**
- Records who replayed which delivery and when
- Metadata includes original attempt number, event type

### Secret rotation

- `POST /api/v1/webhooks/{id}/rotate-secret` generates and encrypts a new secret
- In-flight deliveries using the old secret fail; retries use the new secret (re-decrypted at execution time)
- No stale-secret deliveries are created; the webhook row is the source of truth

### Manual replay

- Authorization: DEVELOPER or ADMIN role only
- Idempotency: reuses the same `eventId` in the envelope (integrator deduplicates on `X-EarnProof-Delivery` header)
- Audit: `AuditLog` entry created with actor and timestamp
- Creates a new `WebhookDelivery` row with `replayOf` pointing to the original

## Prisma schema changes

### New model: `WebhookDeliveryStatus` enum
- `PENDING` – awaiting or scheduled for delivery
- `SUCCESS` – successfully delivered (HTTP 2xx)
- `FAILED` – permanently failed (max attempts exceeded or SSRF block)

### New model: `WebhookDelivery`
- Tracks all delivery attempts per event
- Persists retry state, response metadata, and audit trail
- Indexes on `(webhookId, createdAt)`, `(eventId)`, `(status, nextRetryAt)` for efficient retry scheduling

### Webhook model changes
- **Field rename:** `secretHash` → `secretEncrypted`
  - Old field stored a hash (source of truth loss)
  - New field stores AES-256-GCM encrypted raw secret
  - Requires migration: old rows must be updated or dropped (no production data affected)
- **New relation:** `deliveries WebhookDelivery[]`

## Implementation details

### No external queue dependency
- Retries scheduled via `setTimeout` with in-process Promise chains
- Durable state persisted in `WebhookDelivery` rows
- On service startup, pending deliveries are re-enqueued from DB
- Solves the zero-new-dependencies constraint while maintaining reliability

### Per-webhook ordering chain
- Each webhook has a `Map<webhookId, { tail: Promise<void> }>` chain
- All deliveries for a webhook serialize on the chain tail
- Enforces FIFO ordering and prevents concurrent delivery reordering

### Fire-and-forget emission
- `ProofsService` calls `webhookDeliveryService.enqueueForUser()` with `void` prefix
- Webhook delivery failures do not block proof lifecycle
- Async, non-blocking design

### Organization resolution
- User JWT contains only `userId` (no `orgId`)
- At dispatch, resolve user's organizations and find active, subscribed webhooks
- At endpoint management, resolve user's first ACTIVE organization
- Supports future multi-org scenarios without breaking changes

## Files added/modified

**New files:**
- `prisma/migrations/20260824000000_signed_webhooks/migration.sql`
- `src/webhooks/webhook-event.types.ts` – allowlisted event types and payload shapes
- `src/webhooks/webhook-signing.service.ts` – HMAC-SHA256 signing/verification
- `src/webhooks/webhook-ssrf-guard.ts` – SSRF IP range blocking
- `src/webhooks/webhook-delivery.service.ts` – retry scheduling, delivery execution, per-webhook ordering
- `src/webhooks/webhooks.service.ts` – endpoint management (create, rotate, disable, delete, replay)
- `src/webhooks/webhooks.controller.ts` – REST API routes
- `src/webhooks/webhooks.module.ts` – NestJS module
- `src/webhooks/dto/create-webhook.dto.ts` – validated DTO
- `src/webhooks/dto/update-webhook-events.dto.ts` – validated DTO
- `src/webhooks/webhook-signing.service.spec.ts` – tests
- `src/webhooks/webhook-ssrf-guard.spec.ts` – tests
- `src/webhooks/webhook-delivery.service.spec.ts` – tests (signing, retries, SSRF, redaction, replay)
- `src/webhooks/webhooks.service.spec.ts` – tests (secret rotation, authorization)

**Modified files:**
- `prisma/schema.prisma` – Webhook schema update, WebhookDelivery model addition
- `src/app.module.ts` – import WebhooksModule
- `src/proofs/proofs.module.ts` – import WebhooksModule
- `src/proofs/proofs.service.ts` – add WebhookDeliveryService injection, emit webhooks at lifecycle events

## Trade-offs

1. **No BullMQ/external queue:** In-process `setTimeout` + Promise chains with DB-persisted state. Simpler (zero new deps), durable (survives restarts if shutdown is clean), sufficient for moderate scale. Scaling beyond single-instance requires adding BullMQ later.

2. **In-memory per-webhook chains:** Each chain keeps a single Promise; if the service crashes before all retries complete, in-flight chains are lost. Mitigated by startup replay of PENDING deliveries. Acceptable trade-off for simplicity.

3. **SSRF check is syntactic only:** No DNS lookup (avoids heavy dependency and blocking I/O at enqueue time). Does not protect against DNS-rebinding attacks; network egress firewall provides complementary defence.

4. **Organization lookup at dispatch:** Every webhook event does a DB query to find orgs → webhooks. No caching. Acceptable because queries are indexed and organization membership is not expected to change frequently during delivery.

5. **Single active org per user in controller:** Simplified org resolution (picks first ACTIVE org). Controller code assumes single org. Multi-org scenario would require passing `orgId` as a path param or header.

All trade-offs are documented and within scope.

## Test coverage

**Signature verification:**
- ✓ Valid signature accepted
- ✓ Tampered payload rejected
- ✓ Different secret rejects signature
- ✓ Constant-time comparison prevents length-extension

**Retry behavior:**
- ✓ HTTP 2xx marked SUCCESS, no retry
- ✓ HTTP 5xx creates retry delivery row with same eventId
- ✓ Max attempts (5) prevents further retries
- ✓ eventId consistent across all retry attempts
- ✓ Exponential backoff delays computed correctly

**SSRF protection:**
- ✓ Blocks loopback (127.x, ::1, localhost)
- ✓ Blocks private ranges (10.x, 172.16–31.x, 192.168.x)
- ✓ Blocks link-local and cloud metadata (169.254.x, fe80::, fc00::)
- ✓ Blocks special-use (0.x, 240.x, 255.255.255.255)
- ✓ Blocks non-HTTPS schemes
- ✓ Blocks local domain patterns (*.local, *.internal)
- ✓ SSRF blocks are permanent (no retry scheduled)

**Redaction:**
- ✓ Raw signing secret never stored in delivery rows
- ✓ Response bodies truncated at 1,024 bytes
- ✓ Truncation includes `"…[truncated]"` suffix

**Secret rotation:**
- ✓ New secret generated on rotation
- ✓ Old secret invalidated for signature verification
- ✓ Retry deliveries re-decrypt at execution time (use new secret)
- ✓ In-flight deliveries fail once, retry with new secret

**Manual replay:**
- ✓ Creates new delivery with same eventId (integrator deduplicates)
- ✓ replayOf field links to original delivery
- ✓ replayedBy records the actor
- ✓ Authorization: DEVELOPER/ADMIN only
- ✓ Throws for non-existent delivery
- ✓ Throws for delivery from different org
- ✓ Throws for disabled webhook endpoint
- ✓ AuditLog entry created with metadata

## Verification

All required tests pass:

```bash
npm run lint
# ✓ No ESLint errors

npm run test -- --runInBand
# ✓ All webhook tests pass
# ✓ Existing tests remain passing (no regressions)

npm run build
# ✓ TypeScript compilation successful
# ✓ Prisma migration validates
```

## Deployer notes

1. Run `prisma migrate deploy` to apply the new migration
2. Existing `Webhook` rows with `secretHash` will be dangling (no production data exists)
3. All new webhooks use encrypted secrets
4. Start the service; on first boot, `WebhookDeliveryService.onModuleInit()` scans for pending deliveries (none on fresh start)
5. Test webhook creation and delivery via the endpoint management API
6. Manual replay requires DEVELOPER or ADMIN role

## Future work (out of scope)

- Add BullMQ for multi-instance queue distribution
- Add webhook event filtering (besides allowlist)
- Add batch delivery endpoints (reduce per-event overhead)
- Add circuit breaker pattern (skip unhealthy endpoints)
- Add monitoring/metrics on delivery latency and failure rates
- Add webhook signature header documentation to API reference
- Add UI for webhook management (currently API-only)
