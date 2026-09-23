import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsNotEmpty } from "class-validator";

/**
 * Request to revoke a specific session.
 * The session must belong to the authenticated user (enforced server-side).
 */
export class RevokeSessionRequestDto {
  @ApiProperty({
    description: "The session ID to revoke (not the bearer token).",
    example: "sess_abc123def456",
  })
  @IsString()
  @IsNotEmpty()
  sessionId!: string;
}
