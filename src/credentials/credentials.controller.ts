import { Body, Controller, HttpCode, Post } from "@nestjs/common";
import { ApiTags } from "@nestjs/swagger";
import { Throttle } from "@nestjs/throttler";
import { CredentialsService } from "./credentials.service";
import { VerifyCredentialDto } from "./dto/verify-credential.dto";

@ApiTags("credentials")
@Controller("credentials")
export class CredentialsController {
  constructor(private readonly credentialsService: CredentialsService) {}

  /** Verify a portable credential submitted by a third party. */
  @Post("verify")
  @Throttle({ default: { ttl: 60_000, limit: 10 } })
  @HttpCode(200)
  verifyCredential(@Body() body: VerifyCredentialDto) {
    return this.credentialsService.verifyCredential(body.credential);
  }
}
