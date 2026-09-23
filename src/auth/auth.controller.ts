import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards, BadRequestException, NotFoundException } from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedSession } from "./auth.types";
import { AuthService } from "./auth.service";
import { ChallengeResponseDto } from "./dto/challenge-response.dto";
import { CreateChallengeDto } from "./dto/create-challenge.dto";
import { ListSessionsResponseDto, SessionSummaryDto } from "./dto/list-sessions-response.dto";
import { LogoutResponseDto } from "./dto/logout-response.dto";
import { RevokeSessionRequestDto } from "./dto/revoke-session-request.dto";
import { RevokeSessionResponseDto, RevokeAllOtherSessionsResponseDto } from "./dto/revoke-session-response.dto";
import { RotateResponseDto } from "./dto/rotate-response.dto";
import { SessionResponseDto } from "./dto/session-response.dto";
import { VerifyChallengeDto } from "./dto/verify-challenge.dto";
import { VerifyResponseDto } from "./dto/verify-response.dto";
import { SessionService } from "./session.service";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly sessionService: SessionService,
  ) {}

  @ApiOperation({
    summary: "Request a wallet challenge",
    description:
      "Returns a message that the client must sign with the Stellar wallet identified by " +
      "`walletAddress`. The challenge expires in 5 minutes and can be used only once.",
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Challenge created successfully.",
    type: ChallengeResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Request body failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: "The wallet address is not a valid Stellar Ed25519 public key.",
    type: ApiErrorDto,
  })
  @Post("challenge")
  createChallenge(@Body() body: CreateChallengeDto) {
    return this.authService.createChallenge(body.walletAddress);
  }

  @ApiOperation({
    summary: "Verify a wallet signature and obtain a session token",
    description:
      "Verifies the Ed25519 signature over the challenge message and, if valid, returns a " +
      "Bearer token scoped to the authenticated wallet. The challenge is consumed and cannot " +
      "be replayed.",
  })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: "Signature verified. Session token issued.",
    type: VerifyResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Request body failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: "The wallet address is not a valid Stellar Ed25519 public key.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Challenge expired/used, or wallet signature is invalid.",
    type: ApiErrorDto,
  })
  @Post("verify")
  verifyChallenge(@Body() body: VerifyChallengeDto) {
    return this.authService.verifyChallenge(body);
  }

  @ApiOperation({
    summary: "Return the current session user",
    description: "Returns the full profile of the authenticated user from the database.",
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Current session details.",
    type: SessionResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, or expired.",
    type: ApiErrorDto,
  })
  @UseGuards(AuthGuard)
  @Get("session")
  getSession(@CurrentUser() session: AuthenticatedSession) {
    return this.authService.getSession(session.id);
  }

  @ApiOperation({
    summary: "Log out and revoke the active session",
    description:
      "Revokes the authenticated session server-side so its bearer token cannot be reused.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Session revoked successfully.",
    type: LogoutResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, expired, or revoked.",
    type: ApiErrorDto,
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post("logout")
  async logout(@CurrentUser() session: AuthenticatedSession) {
    await this.authService.logout(session.sessionId);
    return { status: "ok" };
  }

  @ApiOperation({
    summary: "Rotate the active session",
    description:
      "Atomically revokes the current session and returns a fresh opaque bearer token.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Session rotated successfully.",
    type: RotateResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "The active session is unavailable, expired, or already revoked.",
    type: ApiErrorDto,
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post("rotate")
  async rotate(@CurrentUser() session: AuthenticatedSession) {
    const { token, sessionId, expiresAt } = await this.sessionService.rotate(
      session.sessionId,
      session,
    );

    return { token, tokenType: "Bearer", sessionId, expiresAt };
  }

  @ApiOperation({
    summary: "List all sessions for the authenticated user",
    description:
      "Returns all sessions (active, revoked, and expired) with safe, non-sensitive metadata. " +
      "Does not include raw tokens or full fingerprints. Scoped to the authenticated user only.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Sessions retrieved successfully.",
    type: ListSessionsResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, expired, or revoked.",
    type: ApiErrorDto,
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Get("sessions")
  async listSessions(@CurrentUser() session: AuthenticatedSession) {
    const sessions = await this.sessionService.listSessions(
      session.userId,
      session.sessionId,
    );

    // Transform Date objects to ISO-8601 strings for the DTO
    const sessionSummaries: SessionSummaryDto[] = sessions.map((s) => ({
      sessionId: s.sessionId,
      createdAt: s.createdAt.toISOString(),
      expiresAt: s.expiresAt.toISOString(),
      lastUsedAt: s.lastUsedAt?.toISOString() ?? null,
      revokedAt: s.revokedAt?.toISOString() ?? null,
      isActive: s.isActive,
      isCurrent: s.isCurrent,
    }));

    const activeCount = sessionSummaries.filter((s) => s.isActive).length;

    return {
      sessions: sessionSummaries,
      totalCount: sessionSummaries.length,
      activeCount,
    };
  }

  @ApiOperation({
    summary: "Revoke a specific other session",
    description:
      "Revokes a session that belongs to the authenticated user. The session is invalidated " +
      "immediately and cannot be used for future requests. Idempotent — revoking an already-revoked " +
      "session returns success. The current session cannot be revoked via this endpoint; use logout instead.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Session revoked successfully.",
    type: RevokeSessionResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, expired, or revoked.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: "Request body failed validation.",
    type: ApiErrorDto,
  })
  @ApiResponse({
    status: HttpStatus.NOT_FOUND,
    description: "The session does not exist or does not belong to the authenticated user.",
    type: ApiErrorDto,
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post("sessions/revoke")
  async revokeSpecificSession(
    @CurrentUser() session: AuthenticatedSession,
    @Body() body: RevokeSessionRequestDto,
  ) {
    // Prevent users from accidentally revoking their current session via this endpoint
    if (body.sessionId === session.sessionId) {
      throw new BadRequestException(
        "Cannot revoke current session via this endpoint. Use POST /auth/logout instead.",
      );
    }

    const revoked = await this.sessionService.revokeSpecificSession(
      body.sessionId,
      session.userId,
    );

    if (!revoked) {
      throw new NotFoundException(
        "Session not found or does not belong to you.",
      );
    }

    return {
      sessionId: body.sessionId,
      status: "Session revoked successfully",
    };
  }

  @ApiOperation({
    summary: "Revoke all other sessions",
    description:
      "Revokes all active sessions for the authenticated user except the current one. " +
      "Useful for forcing logout on all other devices after a suspected compromise. " +
      "The current session is always preserved. Returns the count of sessions revoked.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "All other sessions revoked successfully.",
    type: RevokeAllOtherSessionsResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: "Bearer token is missing, malformed, invalid, expired, or revoked.",
    type: ApiErrorDto,
  })
  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post("sessions/revoke-all-others")
  async revokeAllOtherSessions(@CurrentUser() session: AuthenticatedSession) {
    const revokedCount = await this.sessionService.revokeAllOtherSessions(
      session.userId,
      session.sessionId,
    );

    return {
      revokedCount,
      currentSessionId: session.sessionId,
      status: `${revokedCount} other sessions revoked successfully`,
    };
  }
}
