# Signed Webhooks Implementation - Deployment Checklist

## Issue
veridatum-labs/earnproof-backend #15: Implement signed webhooks with retries and delivery logs

## Branch
`feat/signed-webhooks`

## Commit Message
`feat(api): add signed webhook delivery`

## Files Created/Modified

### Schema and Migrations
- ✅ `prisma/schema.prisma` – Updated Webhook model, added WebhookDelivery model and WebhookDeliveryStatus enum
- ✅ `prisma/migrations/20260824000000_signed_webhooks/migration.sql` – Migration file with DDL

### Webhook Module (New)
- ✅ `src/webhooks/webhook-event.types.ts` – Allowlisted event types, versioned payload envelopes
- ✅ `src/webhooks/webhook-signing.service.ts` – HMAC-SHA256 signing/verification
- ✅ `src/webhooks/webhook-ssrf-guard.ts` – SSRF protection (IP range blocking)
- ✅ `src/webhooks/webhook-delivery.service.ts` – Delivery execution, retries, ordering, startup recovery
- ✅ `src/webhooks/webhooks.service.ts` – Endpoint management, secret rotation, replay
- ✅ `src/webhooks/webhooks.controller.ts` – REST API routes
- ✅ `src/webhooks/webhooks.module.ts` – NestJS module definition
- ✅ `src/webhooks/dto/create-webhook.dto.ts` – Validated DTO
- ✅ `src/webhooks/dto/update-webhook-events.dto.ts` – Validated DTO

### Test Suite (New)
- ✅ `src/webhooks/webhook-signing.service.spec.ts`
- ✅ `src/webhooks/webhook-ssrf-guard.spec.ts`
- ✅ `src/webhooks/webhook-delivery.service.spec.ts`
- ✅ `src/webhooks/webhooks.service.spec.ts`

### Integration
- ✅ `src/proofs/proofs.service.ts` – Added WebhookDeliveryService injection, webhook emissions at 3 lifecycle events
- ✅ `src/proofs/proofs.module.ts` – Added WebhooksModule import
- ✅ `src/app.module.ts` – Added WebhooksModule import

### Documentation
- ✅ `PR_DESCRIPTION.md` – Complete PR description with design, trade-offs, test coverage

## Pre-Deployment Validation

### 1. Code Quality
```bash
npm run lint
# Expected: No errors, all files pass ESLint
```

### 2. Test Suite
```bash
npm run test -- --runInBand
# Expected: All webhook tests pass + no regressions in existing tests
```

### 3. Build
```bash
npm run build
# Expected: No TypeScript compilation errors
# Prisma types are auto-generated from schema
```

### 4. Schema Validation
```bash
# The migration file includes:
# - Rename Webhook.secretHash → secretEncrypted
# - Create WebhookDeliveryStatus enum (PENDING, SUCCESS, FAILED)
# - Create WebhookDelivery table with proper indexes
# - Foreign key from WebhookDelivery → Webhook
```

## Deployment Steps

### 1. Merge the branch
```bash
git checkout main
git merge feat/signed-webhooks
```

### 2. Apply the migration
```bash
npx prisma migrate deploy
# This:
# - Renames secretHash to secretEncrypted on Webhook table
# - Creates WebhookDeliveryStatus enum type
# - Creates WebhookDelivery table
# - Creates 3 indexes for efficient querying
```

### 3. Restart the application
The service will auto-recover on startup:
- `WebhookDeliveryService.onModuleInit()` scans for PENDING deliveries
- Any incomplete deliveries from before restart are re-enqueued
- Delivery Promise chains are reconstructed per webhook

## Feature Overview

### 1. Event Types (Allowlisted)
- `proof.created` – after proof is created and optionally anchored
- `proof.revoked` – after proof is revoked
- `proof.verified` – after verification result is recorded

### 2. Signing
- **Algorithm:** HMAC-SHA256
- **Signature Header:** `X-EarnProof-Signature: v1=<hex>`
- **Verification Base String:** `timestamp.deliveryId.jsonBody`
- **Headers Sent:**
  - `X-EarnProof-Timestamp` – Unix seconds
  - `X-EarnProof-Delivery` – Delivery ID (idempotency key)
  - `X-EarnProof-Event` – Event type
  - `X-EarnProof-Signature` – Signature with v1= prefix

### 3. Retry Strategy
- Maximum 5 attempts
- Exponential backoff: 1s, 2s, 4s, 8s delays
- SSRF blocks are permanent (no retry)
- Same eventId used across all retry attempts

### 4. Ordering Guarantees
- Per-webhook FIFO serialization via Promise chains
- In-memory implementation (survives restarts via DB state)
- Prevents delivery reordering for the same endpoint

### 5. SSRF Protection
Blocks delivery to:
- Loopback (127.x, ::1, localhost)
- Private ranges (10.x, 172.16–31.x, 192.168.x)
- Link-local (169.254.x, fe80::)
- Cloud metadata (169.254.169.254, 100.100.100.200)
- Special-use (0.x, 240.x, 255.255.255.255)
- Non-HTTPS schemes

### 6. Secret Management
- Stored encrypted (AES-256-GCM)
- Never appears in logs or delivery rows
- Rotation generates new secret, invalidates old one
- Retries re-decrypt at execution time (use new secret after rotation)

### 7. Redaction
- Raw signing secret never stored in delivery logs
- Response bodies truncated at 1,024 bytes
- Failure reasons logged (useful for debugging)
- Audit trail on manual replay

### 8. Manual Replay
- Requires DEVELOPER or ADMIN role
- Idempotent: reuses same eventId (integrator deduplicates)
- Creates new WebhookDelivery row with `replayOf` field
- Audit log entry recorded with actor and timestamp

## API Endpoints

### Create webhook
```
POST /api/v1/webhooks
Authorization: Bearer <token>
{
  "url": "https://example.com/webhooks/earn",
  "events": ["proof.created", "proof.verified"]
}
```
Returns: `{ id, url, events, signingSecret, status, createdAt }`
⚠️ Signing secret returned **only at creation time**, never again

### List webhooks
```
GET /api/v1/webhooks
Authorization: Bearer <token>
```

### Get webhook
```
GET /api/v1/webhooks/{id}
Authorization: Bearer <token>
```

### Update subscriptions
```
PATCH /api/v1/webhooks/{id}/events
Authorization: Bearer <token>
{
  "events": ["proof.created"]
}
```

### Rotate secret
```
POST /api/v1/webhooks/{id}/rotate-secret
Authorization: Bearer <token>
```
Returns: `{ webhookId, signingSecret, rotatedAt }`

### Disable endpoint
```
PATCH /api/v1/webhooks/{id}/disable
Authorization: Bearer <token>
```

### Enable endpoint
```
PATCH /api/v1/webhooks/{id}/enable
Authorization: Bearer <token>
```

### Delete endpoint
```
DELETE /api/v1/webhooks/{id}
Authorization: Bearer <token>
```

### View deliveries
```
GET /api/v1/webhooks/{id}/deliveries
Authorization: Bearer <token>
```

### Manual replay (DEVELOPER/ADMIN only)
```
POST /api/v1/webhooks/deliveries/{deliveryId}/replay
Authorization: Bearer <token>
```

## Trade-offs and Notes

### 1. In-Process Retry (No BullMQ)
- **Trade-off:** Retries scheduled via `setTimeout`, not a durable queue
- **Mitigation:** Delivery state persisted in DB; pending deliveries re-enqueued on startup
- **Future:** Can add BullMQ later without breaking changes

### 2. Per-Webhook Memory Chains
- **Trade-off:** FIFO ordering enforced in-memory via Promise chains
- **Mitigation:** DB persists delivery state; startup replays pending deliveries
- **Limitation:** Chains lost if process crashes before all retries complete

### 3. SSRF Check is Syntactic Only
- **Trade-off:** No DNS resolution (avoids blocking I/O, no heavy dependencies)
- **Limitation:** Does not protect against DNS-rebinding attacks
- **Mitigation:** Network-layer egress firewall provides complementary defence

### 4. Organization Lookup at Dispatch
- **Trade-off:** Every webhook event queries DB to find org → webhooks
- **Rationale:** No orgId in JWT; org membership is not expected to change frequently
- **Index:** Webhook has `@@index([organizationId, status])` for efficient lookup

### 5. Single-Org Per User in Controller
- **Trade-off:** Controller resolves first ACTIVE organization for the user
- **Rationale:** Simplifies org resolution; multi-org would require passing orgId as param
- **Future:** Can add per-endpoint org ID param without breaking changes

## Monitoring Recommendations

### Log for Failures
- `WebhookDeliveryService` logs all delivery attempts
- Watch for SSRF blocks (permanent failures)
- Track retry rates and backoff delays

### Audit Trail
- All manual replays are logged in `AuditLog` with actor and timestamp
- All secret rotations update the Webhook row (audit via `updatedAt`)

### Health Checks
- Monitor `WebhookDelivery` rows with `status = PENDING` and old `nextRetryAt`
- Alert if pending deliveries are not progressing

## Rollback Plan

If issues are discovered post-deployment:

1. **Disable webhooks temporarily:**
   ```sql
   UPDATE "Webhook" SET status = 'SUSPENDED' WHERE status = 'ACTIVE';
   ```

2. **Revert the migration:**
   ```bash
   npx prisma migrate resolve --rolled-back 20260824000000_signed_webhooks
   ```

3. **Revert the code:**
   ```bash
   git revert <commit-hash>
   ```

4. **Restart the service**

5. **Contact integrators** about the incident

## Success Criteria

- ✅ All new tests pass
- ✅ Existing tests have no regressions
- ✅ Lint and build successful
- ✅ Migration applies cleanly
- ✅ Webhooks can be created/rotated/replayed via API
- ✅ Proof lifecycle events emit webhooks
- ✅ Deliveries are signed and can be verified by integrators
- ✅ SSRF-blocked URLs are rejected permanently
- ✅ Secrets are not leaked in logs or delivery rows
- ✅ Manual replay is audited and idempotent
