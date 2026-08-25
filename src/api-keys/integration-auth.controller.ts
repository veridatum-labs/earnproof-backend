import { Controller, Get, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { ApiKeyScope } from "@prisma/client";
import { CurrentApiKey } from "../common/decorators/current-api-key.decorator";
import { RequireScopes } from "../common/decorators/require-scopes.decorator";
import { ApiKeyGuard } from "../common/guards/api-key.guard";
import { ScopesGuard } from "../common/guards/scopes.guard";
import { ApiKeyContext } from "./api-key.types";

@ApiTags("integrations")
@ApiBearerAuth()
@Controller("integrations")
export class IntegrationAuthController {
  @Get("auth-context")
  @UseGuards(ApiKeyGuard, ScopesGuard)
  @RequireScopes(ApiKeyScope.ORG_READ)
  @ApiOperation({
    summary: "Validate an integration key and return its safe organization context",
  })
  authContext(@CurrentApiKey() context: ApiKeyContext) {
    return {
      keyId: context.keyId,
      prefix: context.prefix,
      organizationId: context.organizationId,
      scopes: context.scopes,
    };
  }
}
