import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/**
 * Safe, minimal session metadata exposed to the user.
 * Never includes raw tokens, refresh tokens, or full fingerprints.
 * Only includes information needed for the user to recognize and distinguish sessions.
 */
export class SessionSummaryDto {
  @ApiProperty({
    description: "The session ID (not the bearer token).",
    example: "sess_abc123def456",
  })
  sessionId!: string;

  @ApiProperty({
    description: "ISO-8601 UTC timestamp when the session was created.",
    example: "2025-01-15T10:00:00.000Z",
  })
  createdAt!: string;

  @ApiProperty({
    description: "ISO-8601 UTC timestamp when the session will expire.",
    example: "2025-01-15T22:00:00.000Z",
  })
  expiresAt!: string;

  @ApiPropertyOptional({
    description:
      "ISO-8601 UTC timestamp of the last activity on this session. Null if never used since creation.",
    example: "2025-01-15T11:30:00.000Z",
    nullable: true,
  })
  lastUsedAt!: string | null;

  @ApiPropertyOptional({
    description:
      "ISO-8601 UTC timestamp when this session was revoked. Null if still active. " +
      "Present only in sessions that have been explicitly revoked (not yet expired).",
    example: null,
    nullable: true,
  })
  revokedAt!: string | null;

  @ApiProperty({
    description: "Whether this session is currently active (not revoked and not expired).",
    example: true,
  })
  isActive!: boolean;

  @ApiProperty({
    description: "Whether this is the current authenticated session making the request.",
    example: true,
  })
  isCurrent!: boolean;
}

export class ListSessionsResponseDto {
  @ApiProperty({
    type: [SessionSummaryDto],
    description: "Array of all sessions for the authenticated user, including the current one.",
  })
  sessions!: SessionSummaryDto[];

  @ApiProperty({
    type: Number,
    description: "Total number of sessions (including revoked and expired, for audit purposes).",
    example: 5,
  })
  totalCount!: number;

  @ApiProperty({
    type: Number,
    description: "Number of currently active sessions.",
    example: 3,
  })
  activeCount!: number;
}
