import { ApiProperty } from "@nestjs/swagger";

/**
 * Response for revoking a single session.
 * Returns the revoked session ID and confirms success.
 */
export class RevokeSessionResponseDto {
  @ApiProperty({
    description: "The session ID that was revoked.",
    example: "sess_abc123def456",
  })
  sessionId!: string;

  @ApiProperty({
    description: "Status message confirming the revocation.",
    example: "Session revoked successfully",
  })
  status!: string;
}

/**
 * Response for revoking all other sessions.
 * Returns the count of sessions that were revoked and the current session ID (which was preserved).
 */
export class RevokeAllOtherSessionsResponseDto {
  @ApiProperty({
    description:
      "Number of other sessions that were revoked. Does not include the current session.",
    example: 3,
  })
  revokedCount!: number;

  @ApiProperty({
    description: "The current session ID (preserved from revocation).",
    example: "sess_current123abc",
  })
  currentSessionId!: string;

  @ApiProperty({
    description: "Status message confirming the revocation of all other sessions.",
    example: "3 other sessions revoked successfully",
  })
  status!: string;
}
