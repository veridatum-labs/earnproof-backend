import { Body, Controller, Get, HttpCode, HttpStatus, Post, UseGuards } from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedUser } from "./auth.types";
import { AuthService } from "./auth.service";
import { ChallengeResponseDto } from "./dto/challenge-response.dto";
import { CreateChallengeDto } from "./dto/create-challenge.dto";
import { LogoutResponseDto } from "./dto/logout-response.dto";
import { SessionResponseDto } from "./dto/session-response.dto";
import { VerifyChallengeDto } from "./dto/verify-challenge.dto";
import { VerifyResponseDto } from "./dto/verify-response.dto";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
  getSession(@CurrentUser() user: AuthenticatedUser) {
    return this.authService.getSession(user.id);
  }

  @ApiOperation({
    summary: "Log out (client-side token invalidation)",
    description:
      "Signals logout intent. Because tokens are stateless HMAC tokens the server has no " +
      "token store to clear; the client must discard the token. Returns a confirmation envelope.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Logout acknowledged.",
    type: LogoutResponseDto,
  })
  @HttpCode(HttpStatus.OK)
  @Post("logout")
  logout(): LogoutResponseDto {
    return { status: "ok" };
  }
}
