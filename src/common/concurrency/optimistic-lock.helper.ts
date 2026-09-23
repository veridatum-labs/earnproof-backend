import { ConflictException } from '@nestjs/common';
import { ApiErrorCode } from '../dto/api-error.dto';

/**
 * Represents a conflict error when optimistic locking fails.
 * Includes the current revision so clients can retry with the updated value.
 */
export interface OptimisticLockConflictError {
  currentRevision: number;
}

/**
 * Configuration for optimistic lock operations.
 */
export interface OptimisticLockConfig {
  /**
   * The resource type name for error messages (e.g., "Organization", "Issuer")
   */
  resourceType: string;
  /**
   * The resource ID for error messages
   */
  resourceId: string;
  /**
   * The expected revision provided by the client
   */
  expectedRevision: number;
  /**
   * The current revision in the database
   */
  currentRevision: number;
}

/**
 * Helper for optimistic concurrency control on mutable administrative resources.
 *
 * This helper enforces "check-then-update" semantics: only allow an update if
 * the expected revision matches the current stored revision. If not, return a
 * 409 Conflict with the current revision so the client can retry with the
 * updated value.
 *
 * All update operations must use this helper to ensure atomicity: the revision
 * check and increment happen in the same transaction, with no window where
 * the data changes without the revision changing.
 */
export class OptimisticLockHelper {
  /**
   * Validates that the client-supplied expected revision matches the current
   * stored revision. Throws ConflictException with status 409 if they don't match.
   *
   * This should be called inside the transaction before applying the update.
   *
   * @param config Configuration with resourceType, resourceId, expectedRevision, currentRevision
   * @throws ConflictException (409) if expectedRevision !== currentRevision
   */
  static checkRevision(config: OptimisticLockConfig): void {
    if (config.expectedRevision !== config.currentRevision) {
      throw new ConflictException(
        JSON.stringify({
          code: ApiErrorCode.CONFLICT,
          message: `${config.resourceType} ${config.resourceId} has been modified. Expected revision ${config.expectedRevision}, but current revision is ${config.currentRevision}. Please refresh and retry.`,
          currentRevision: config.currentRevision,
        }),
      );
    }
  }

  /**
   * Increments the revision field and returns the new revision.
   * This should be called within the same transaction as the data update
   * to ensure atomicity.
   *
   * The caller is responsible for including this in the WHERE clause of
   * their update query to ensure only records matching the expected revision
   * are updated (double-check pattern for extra safety).
   *
   * @param currentRevision The current revision value
   * @returns The new revision value (currentRevision + 1)
   */
  static incrementRevision(currentRevision: number): number {
    return currentRevision + 1;
  }
}
