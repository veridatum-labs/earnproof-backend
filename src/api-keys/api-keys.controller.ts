import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiTags,
} from "@nestjs/swagger";
import { AuthenticatedUser } from "../auth/auth.types";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { ApiKeysService } from "./api-keys.service";
import { CreateApiKeyDto } from "./dto/create-api-key.dto";

@ApiBearerAuth()
@ApiTags("api-keys")
@UseGuards(AuthGuard)
@Controller("organizations/:organizationId/api-keys")
export class ApiKeysController {
  constructor(private readonly apiKeysService: ApiKeysService) {}

  @ApiOperation({ summary: "Create a new API key for an organization" })
  @ApiParam({ name: "organizationId", description: "Organization ID" })
  @Post()
  create(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Body() dto: CreateApiKeyDto,
  ) {
    return this.apiKeysService.createApiKey(user, organizationId, dto);
  }

  @ApiOperation({ summary: "List API key metadata for an organization" })
  @ApiParam({ name: "organizationId", description: "Organization ID" })
  @Get()
  list(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
  ) {
    return this.apiKeysService.listApiKeys(user, organizationId);
  }

  @ApiOperation({
    summary: "Rotate an API key (invalidates old key, returns new secret once)",
  })
  @ApiParam({ name: "organizationId", description: "Organization ID" })
  @ApiParam({ name: "id", description: "API key ID" })
  @Put(":id/rotate")
  rotate(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("id") id: string,
  ) {
    return this.apiKeysService.rotateApiKey(user, organizationId, id);
  }

  @ApiOperation({ summary: "Revoke an API key" })
  @ApiParam({ name: "organizationId", description: "Organization ID" })
  @ApiParam({ name: "id", description: "API key ID" })
  @Delete(":id")
  revoke(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("id") id: string,
  ) {
    return this.apiKeysService.revokeApiKey(user, organizationId, id);
  }
}
