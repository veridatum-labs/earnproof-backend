## Description

Adds three authentication hardening layers to the EarnProof API on top of the existing SEP-53 challenge/verify flow:

1. **Rate limiting** — a Redis-backed fixed-window counter (INCR + EXPIRE) enforced via a NestJS `RateLimitGuard` on `POST /auth/challenge` and `POST /auth/verify`. Each endpoint has independent, configurable limits keyed by `sha256(walletAddress)` so no raw wallet addresses or IP addresses are stored in Redis. Requests that exceed the limit receive a stable HTTP 429 with a `retryAfter` field in seconds.

2. **Challenge cleanup** — a `ChallengeCleanupService` that runs on a configurable cron schedule and removes expired (`expiresAt < now`) and sufficiently old used (`usedAt < now - retention`) `WalletChallenge` rows in bounded batches to prevent unbounded table growth. The job is registered programmatically via `SchedulerRegistry.addCronJob()` so the cron expression can be read from config at runtime.

3. **Persistent audit events** — a fire-and-forget `AuditService` that writes privacy-safe rows to the existing `AuditLog` table for every significant auth outcome: `auth.challenge.created`, `auth.login.success`, and `auth.login.failed` (with sub-reasons `invalid_signature`, `challenge_unavailable`, `rate_limited`). Raw wallet addresses, signatures, and challenge messages are never stored; the hashed wallet address goes into a new `actorHash` column (no FK constraint) while `actorId` is reserved for the `auth.login.success` path where a real `User.id` is available.

All three subsystems are failure-isolated: Redis unavailability and audit write failures degrade gracefully and never block or unintentionally authenticate a request.

## Related issue

Closes #[issue number]

## Type of change

- [x] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Documentation
- [x] Test, migration, or build improvement

## Changes made

- Added `src/common/redis/redis.module.ts` and `redis.provider.ts` — global `@Global()` NestJS module exposing an `ioredis` client via `REDIS_CLIENT` token with `enableOfflineQueue: false` for fast-fail degradation
- Added `src/auth/rate-limit/rate-limit.service.ts` — fixed-window INCR + EXPIRE counter; key = `rl:{namespace}:{sha256(walletAddress)}`; Redis failures return `{ allowed: true }` and emit a `warn` log
- Added `src/auth/rate-limit/rate-limit.guard.ts` — `CanActivate` guard that reads namespace from `@SetMetadata`, checks the limit, fires an audit event, and throws HTTP 429 with `retryAfter` on rejection
- Added `src/auth/audit/audit.service.ts` — fire-and-forget wrapper around `prisma.auditLog.create()`; stores `actorHash: sha256(walletAddress)`, never raw addresses or signatures; errors are `.catch()`-swallowed
- Added `src/auth/cleanup/challenge-cleanup.service.ts` — bounded `findMany → deleteMany` cleanup job registered via `SchedulerRegistry`; logs deletion count; errors swallowed so cron continues
- Updated `src/auth/auth.service.ts` — wires `AuditService` calls at all four outcome paths (challenge created, login success, invalid signature, challenge unavailable)
- Updated `src/auth/auth.controller.ts` — applies `@SetMetadata` + `@UseGuards(RateLimitGuard)` to both auth endpoints
- Updated `src/auth/auth.module.ts` — registers all new providers
- Updated `src/app.module.ts` — imports `RedisModule` (global) and `ScheduleModule.forRoot()`
- Updated `prisma/schema.prisma` — additive `actorHash String?` column + `@@index([actorType, actorHash])` on `AuditLog`; new migration `add_audit_log_actor_hash`
- Updated `src/config/env.validation.ts` — added 7 new validated env vars with Zod defaults; non-positive integers for rate-limit vars cause startup validation errors
- Updated `src/config/configuration.ts` — added `auth.challenge.*`, `auth.verify.*`, `auth.cleanup.*` config sections with `Number(process.env.VAR ?? default)` pattern
- Added unit tests for `RateLimitService`, `RateLimitGuard`, `AuditService`, `ChallengeCleanupService`, and updated `auth.service.spec.ts`
- Updated `.env.example` with the 7 new environment variables

## Validation

- [x] `npm run prisma:generate`
- [x] `npm run lint`
- [x] `npm test -- --runInBand`
- [x] `npm run build`

## Privacy and security

- [x] No secrets, signing keys, wallet private material, or real payment records were added.
- [x] Public verification output exposes only intentionally disclosed proof data.
- [x] Authentication, authorization, rate-limit, and privacy effects were considered.
- [x] API documentation matches implemented behavior.
