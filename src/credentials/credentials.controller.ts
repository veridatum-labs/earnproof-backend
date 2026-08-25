import {
  Body,
  Controller,
  HttpCode,
  Post,
  UseInterceptors,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import { RequestTimeoutInterceptor } from "../common/interceptors/request-timeout.interceptor";
import { CredentialsService } from "./credentials.service";
import { VerifyCredentialDto } from "./dto/verify-credential.dto";

@ApiTags("credentials")
@Controller("credentials")
export class CredentialsController {
  constructor(private readonly credentialsService: CredentialsService) {}

  /** Verify a portable credential submitted by a third party. */
  @Post("verify")
  @ApiOperation({ summary: "Verify a portable EarnProof credential" })
  @ApiResponse({
    status: 200,
    description: "Credential verification result",
    schema: {
      example: { result: "valid" },
    },
  })
  @ApiResponse({
    status: 400,
    description: "Malformed, oversized, or excessively nested credential",
  })
  @ApiResponse({ status: 408, description: "Verification timed out" })
  @ApiResponse({ status: 429, description: "Rate limit exceeded" })
  @Throttle({ default: { ttl: 60_000, limit: 10 } })
  @UseInterceptors(RequestTimeoutInterceptor)
  @HttpCode(200)
  verifyCredential(@Body() body: VerifyCredentialDto) {
    return this.credentialsService.verifyCredential(body.credential);
  }
}
