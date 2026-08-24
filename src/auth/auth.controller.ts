import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedSession } from "./auth.types";
import { AuthService } from "./auth.service";
import { CreateChallengeDto } from "./dto/create-challenge.dto";
import { VerifyChallengeDto } from "./dto/verify-challenge.dto";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("challenge")
  createChallenge(@Body() body: CreateChallengeDto) {
    return this.authService.createChallenge(body.walletAddress);
  }

  @Post("verify")
  verifyChallenge(@Body() body: VerifyChallengeDto) {
    return this.authService.verifyChallenge(body);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Get("session")
  getSession(@CurrentUser() session: AuthenticatedSession) {
    return this.authService.getSession(session.id);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@CurrentUser() session: AuthenticatedSession) {
    await this.authService.logout(session.sessionId);
    return { status: "ok" };
  }
}
