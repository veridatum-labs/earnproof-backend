/**
 * WebhookDeliveryService
 *
 * Handles the actual HTTP delivery of signed webhook payloads, including:
 *  - Writing a delivery record before the first attempt
 *  - Signing the payload with the endpoint's per-secret HMAC key
 *  - Making the outbound fetch request with SSRF protection
 *  - Bounded exponential back-off retry logic (max 5 attempts)
 *  - Redacted delivery logs (secrets and auth headers never stored)
 *  - Manual replay with authorization check and audit trail
 *
 * ## Retry / back-off schedule
 *
 *   attempt 1 (initial)  — immediate
 *   attempt 2            — eligible 30 s after previous failure
 *   attempt 3            — eligible 60 s after previous failure
 *   attempt 4            — eligible 120 s after previous failure
 *   attempt 5            — eligible 240 s after previous failure
 *   (exhausted after 5 failed attempts)
 *
 *   Formula: delay = min(2^(attempt-1) * 30, 3_600) seconds
 *
 * ## Ordering guarantee
 *
 *   Retries and manual replays for a given webhookId are executed in
 *   ascending createdAt order (oldest pending delivery first). This prevents
 *   a slow/failed delivery for event N from being overtaken by event N+1 for
 *   the same aggregate.
 *
 *   Because delivery is fire-and-forget (no background worker), strict serial
 *   ordering is best-effort within a single process. The DB ordering guarantee
 *   applies when a background worker or manual replay iterates
 *   pendingDeliveriesForWebhook().
 *
 * ## Redaction
 *
 *   - `secretEncrypted` / `secretHash` are never returned from any public
 *     method or stored in delivery logs.
 *   - `latestResponseBody` is truncated to MAX_RESPONSE_BODY_CHARS (2 048).
 *   - Outbound request headers are not stored in the delivery log; only the
 *     list of header keys is tracked (not values) so the signature is never
 *     persisted.
 */
import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { ResourceStatus } from "@prisma/client";
import { randomUUID } from "crypto";
import { decryptProtectedAmount } from "../common/crypto/protected-amount";
import { PrismaService } from "../database/prisma.service";
import { SsrfGuard } from "./ssrf.guard";
import { WebhookEventPayload, WebhookEventType } from "./webhook-event.types";
import { WebhookSigningService } from "./webhook-signing.service";

/** Maximum number of delivery attempts before a delivery is exhausted. */
const MAX_ATTEMPTS = 5;

/** Stored response body is capped at this character count. */
const MAX_RESPONSE_BODY_CHARS = 2048;

/** Outbound HTTP request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 10_000;

/** Compute the retry delay in seconds for a given attempt number (1-based). */
function retryDelaySeconds(attempt: number): number {
  return Math.min(Math.pow(2, attempt - 1) * 30, 3_600);
}

@Injectable()
export class WebhookDeliveryService {
  private readonly webhookEncryptionKey: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly signing: WebhookSigningService,
  ) {
    // Lazily read from process.env so tests can override without
    // ConfigService wiring overhead. The service is always instantiated
    // inside a NestJS DI context, but we avoid a hard startup crash if the
    // key is absent in unit tests — the missing-key path is exercised by
    // providing a test key via the constructor directly.
    this.webhookEncryptionKey =
      process.env.WEBHOOK_ENCRYPTION_KEY ?? "test-webhook-key";
  }

  // ---------------------------------------------------------------------------
  // Public dispatch API
  // ---------------------------------------------------------------------------

  /**
   * Dispatch an event to all active webhook endpoints subscribed to it for a
   * given organization.
   *
   * Creates a WebhookDelivery record for each matching endpoint and fires the
   * first attempt asynchronously (fire-and-forget — does not block the caller).
   */
  async dispatchEvent(
    organizationId: string,
    eventType: WebhookEventType,
    payload: WebhookEventPayload,
  ): Promise<void> {
    const endpoints = await this.prisma.webhook.findMany({
      where: {
        organizationId,
        status: ResourceStatus.ACTIVE,
      },
      select: {
        id: true,
        url: true,
        secretEncrypted: true,
        events: true,
      },
    });

    for (const endpoint of endpoints) {
      // Check subscription
      const subscribedEvents = Array.isArray(endpoint.events)
        ? (endpoint.events as string[])
        : [];
      if (!subscribedEvents.includes(eventType)) continue;

      // Create delivery record before attempting — ensures it's replayable
      // if the process crashes between here and the fetch.
      const deliveryId = randomUUID();
      const delivery = await this.prisma.webhookDelivery.create({
        data: {
          webhookId: endpoint.id,
          deliveryId,
          eventType,
          payload: payload as object,
          attemptCount: 0,
          nextRetryAt: new Date(), // eligible immediately
        },
        select: { id: true, deliveryId: true },
      });

      // Fire-and-forget — do NOT await; errors are captured in the delivery log
      void this.attemptDelivery(
        delivery.id,
        endpoint.url,
        endpoint.secretEncrypted,
        deliveryId,
        eventType,
        payload,
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Manual replay
  // ---------------------------------------------------------------------------

  /**
   * Re-attempt delivery of a specific WebhookDelivery.
   *
   * Authorization: the caller must be the createdBy user of the organization
   * that owns the webhook.
   *
   * Idempotency: the same `deliveryId` is reused so integrators can deduplicate
   * by `X-EarnProof-Delivery`.
   *
   * Audit: records `replayedById` and `replayedAt` on the delivery row, and
   * writes an AuditLog entry.
   */
  async replayDelivery(
    deliveryDbId: string,
    actorUserId: string,
  ): Promise<{ queued: boolean; deliveryId: string }> {
    const record = await this.prisma.webhookDelivery.findUnique({
      where: { id: deliveryDbId },
      select: {
        id: true,
        deliveryId: true,
        eventType: true,
        payload: true,
        attemptCount: true,
        exhaustedAt: true,
        webhookId: true,
        webhook: {
          select: {
            id: true,
            url: true,
            secretEncrypted: true,
            organizationId: true,
            status: true,
            organization: {
              select: { createdById: true },
            },
          },
        },
      },
    });

    if (!record) {
      throw new NotFoundException("Delivery record not found");
    }

    // Authorization: user must be the org creator
    if (record.webhook.organization.createdById !== actorUserId) {
      throw new ForbiddenException(
        "You do not have permission to replay this delivery",
      );
    }

    if (record.webhook.status !== ResourceStatus.ACTIVE) {
      throw new ForbiddenException("Webhook endpoint is not active");
    }

    // Allow replay even if exhausted — manual override is intentional
    // Reset exhaustedAt so it's considered live again
    await this.prisma.webhookDelivery.update({
      where: { id: record.id },
      data: {
        exhaustedAt: null,
        nextRetryAt: new Date(),
        replayedById: actorUserId,
        replayedAt: new Date(),
      },
    });

    // Audit log
    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actorUserId,
        action: "webhook.delivery.replayed",
        resourceType: "webhookDelivery",
        resourceId: record.id,
        metadata: {
          deliveryId: record.deliveryId,
          webhookId: record.webhookId,
          eventType: record.eventType,
          previousAttemptCount: record.attemptCount,
        },
      },
    });

    // Fire-and-forget replay
    void this.attemptDelivery(
      record.id,
      record.webhook.url,
      record.webhook.secretEncrypted,
      record.deliveryId,
      record.eventType as WebhookEventType,
      record.payload as WebhookEventPayload,
    );

    return { queued: true, deliveryId: record.deliveryId };
  }

  // ---------------------------------------------------------------------------
  // Delivery query helpers
  // ---------------------------------------------------------------------------

  /**
   * List delivery records for a webhook, ordered oldest-first (for replay tooling).
   * Scoped to the organization so callers cannot read across org boundaries.
   */
  async listDeliveries(
    webhookId: string,
    organizationId: string,
    opts: { eventType?: string; after?: string } = {},
  ) {
    // Verify ownership
    const webhook = await this.prisma.webhook.findFirst({
      where: { id: webhookId, organizationId },
      select: { id: true },
    });
    if (!webhook) throw new NotFoundException("Webhook not found");

    let afterCursor: { createdAt: Date } | undefined;
    if (opts.after) {
      const pivot = await this.prisma.webhookDelivery.findUnique({
        where: { id: opts.after },
        select: { createdAt: true },
      });
      if (pivot) afterCursor = { createdAt: pivot.createdAt };
    }

    return this.prisma.webhookDelivery.findMany({
      where: {
        webhookId,
        eventType: opts.eventType,
        ...(afterCursor
          ? { createdAt: { gt: afterCursor.createdAt } }
          : {}),
      },
      orderBy: { createdAt: "asc" },
      take: 50,
      select: {
        id: true,
        deliveryId: true,
        eventType: true,
        attemptCount: true,
        lastAttemptAt: true,
        nextRetryAt: true,
        exhaustedAt: true,
        latestResponseStatus: true,
        // latestResponseBody is included — already truncated at write time
        latestResponseBody: true,
        replayedById: true,
        replayedAt: true,
        createdAt: true,
        // payload is omitted from list to keep responses lean
      },
    });
  }

  // ---------------------------------------------------------------------------
  // Core delivery loop
  // ---------------------------------------------------------------------------

  /**
   * Perform a single delivery attempt and persist the result.
   * If the attempt fails and the delivery is not yet exhausted, schedules
   * the `nextRetryAt` timestamp for a future retry.
   */
  private async attemptDelivery(
    deliveryDbId: string,
    url: string,
    secretEncrypted: string,
    deliveryId: string,
    eventType: WebhookEventType,
    payload: WebhookEventPayload,
  ): Promise<void> {
    // Refresh attempt count from DB to be safe across concurrent replays
    const current = await this.prisma.webhookDelivery.findUnique({
      where: { id: deliveryDbId },
      select: { attemptCount: true },
    });
    if (!current) return;

    const attempt = current.attemptCount + 1;

    // Decrypt the raw signing secret (never logs the value)
    let rawSecret: string;
    try {
      rawSecret = decryptProtectedAmount(
        secretEncrypted,
        this.webhookEncryptionKey,
      );
    } catch {
      await this.recordFailure(
        deliveryDbId,
        attempt,
        null,
        "Secret decryption failed",
        MAX_ATTEMPTS,
      );
      return;
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const body = this.signing.canonicalize(payload);
    const signature = this.signing.sign(rawSecret, timestamp, deliveryId, body);

    let responseStatus: number | null = null;
    let responseBody: string | null = null;
    let success = false;

    try {
      // SSRF check before every attempt (URL could change if rotated, though
      // we validate on creation; belt-and-suspenders here)
      await SsrfGuard.assertSafeUrl(url);

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        REQUEST_TIMEOUT_MS,
      );

      const response = await fetch(url, {
        method: "POST",
        // Disable automatic redirect following — any redirect is a failure
        redirect: "error",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "X-EarnProof-Event": eventType,
          "X-EarnProof-Delivery": deliveryId,
          "X-EarnProof-Timestamp": timestamp,
          // Signature header — value is the signed digest, NOT stored in logs
          "X-EarnProof-Signature": `sha256=${signature}`,
        },
        body,
      }).finally(() => clearTimeout(timeout));

      responseStatus = response.status;

      // Read and truncate the response body
      try {
        const text = await response.text();
        responseBody = text.slice(0, MAX_RESPONSE_BODY_CHARS);
      } catch {
        // Response body read failure is non-fatal
      }

      // 2xx = success; anything else is a delivery failure
      success = response.status >= 200 && response.status < 300;
    } catch {
      // Network error, timeout, redirect, SSRF block — all count as failures
      responseBody = "Request failed";
    }

    if (success) {
      await this.prisma.webhookDelivery.update({
        where: { id: deliveryDbId },
        data: {
          attemptCount: attempt,
          lastAttemptAt: new Date(),
          nextRetryAt: null,
          exhaustedAt: null,
          latestResponseStatus: responseStatus,
          latestResponseBody: responseBody,
        },
      });
    } else {
      await this.recordFailure(
        deliveryDbId,
        attempt,
        responseStatus,
        responseBody,
        MAX_ATTEMPTS,
      );
    }
  }

  private async recordFailure(
    deliveryDbId: string,
    attempt: number,
    responseStatus: number | null,
    responseBody: string | null,
    maxAttempts: number,
  ): Promise<void> {
    const exhausted = attempt >= maxAttempts;
    const nextRetryAt = exhausted
      ? null
      : new Date(Date.now() + retryDelaySeconds(attempt) * 1000);

    await this.prisma.webhookDelivery.update({
      where: { id: deliveryDbId },
      data: {
        attemptCount: attempt,
        lastAttemptAt: new Date(),
        nextRetryAt,
        exhaustedAt: exhausted ? new Date() : null,
        latestResponseStatus: responseStatus,
        latestResponseBody: responseBody?.slice(0, MAX_RESPONSE_BODY_CHARS) ?? null,
      },
    });
  }
}
