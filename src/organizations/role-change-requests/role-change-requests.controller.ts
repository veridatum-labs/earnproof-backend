import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from "@nestjs/swagger";
import { Request } from "express";
import { AuthenticatedUser } from "../../auth/auth.types";
import { AuthenticatedRoute } from "../../common/decorators/authorization-policy.decorator";
import { CurrentUser } from "../../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../../common/dto/api-error.dto";
import { AuthGuard } from "../../common/guards/auth.guard";
import { SESSION_AUTH_SCHEME } from "../../common/swagger/security-schemes";
import { ApproveRoleChangeRequestDto } from "./dto/approve-role-change-request.dto";
import { CancelRoleChangeRequestDto } from "./dto/cancel-role-change-request.dto";
import { CreateRoleChangeRequestDto } from "./dto/create-role-change-request.dto";
import { ListRoleChangeRequestsDto } from "./dto/list-role-change-requests.dto";
import { RejectRoleChangeRequestDto } from "./dto/reject-role-change-request.dto";
import { RoleChangeRequestResponseDto } from "./dto/role-change-request-response.dto";
import { RoleChangeRequestsService } from "./role-change-requests.service";

/**
 * Dual-control role change request endpoints (#278).
 *
 * Implements a request and independent approval path for high-impact organization
 * role changes instead of an immediate single-actor mutation.
 */
@ApiBearerAuth(SESSION_AUTH_SCHEME)
@ApiTags("organizations")
@AuthenticatedRoute()
@Controller("organizations/:organizationId/role-change-requests")
@UseGuards(AuthGuard)
@ApiUnauthorizedResponse({ description: "Missing or invalid session.", type: ApiErrorDto })
@ApiNotFoundResponse({ description: "Organization not found.", type: ApiErrorDto })
export class RoleChangeRequestsController {
  constructor(private readonly service: RoleChangeRequestsService) {}

  @Post()
  @ApiOperation({
    summary: "Request a privileged role change",
    description:
      "Initiates a dual-control role change request for an organization member. " +
      "Requires organization ADMIN or OWNER role. The request must be independently approved.",
  })
  @ApiCreatedResponse({ type: RoleChangeRequestResponseDto })
  @ApiBadRequestResponse({ description: "Invalid body or role already held.", type: ApiErrorDto })
  @ApiForbiddenResponse({ description: "Insufficient organization role.", type: ApiErrorDto })
  @ApiConflictResponse({
    description: "Active request already pending for target member, or stale expected revision.",
    type: ApiErrorDto,
  })
  create(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Body() dto: CreateRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    return this.service.create(user, organizationId, dto);
  }

  @Get()
  @ApiOperation({
    summary: "List role change requests",
    description: "Returns paginated role change requests for the organization.",
  })
  @ApiOkResponse({ description: "List of role change requests." })
  @ApiForbiddenResponse({ description: "Not an organization member.", type: ApiErrorDto })
  list(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Query() query: ListRoleChangeRequestsDto,
  ) {
    return this.service.list(user, organizationId, query);
  }

  @Get(":requestId")
  @ApiOperation({
    summary: "Get role change request details",
    description: "Returns full details of a specific role change request.",
  })
  @ApiOkResponse({ type: RoleChangeRequestResponseDto })
  @ApiForbiddenResponse({ description: "Not an organization member.", type: ApiErrorDto })
  @ApiNotFoundResponse({ description: "Request not found.", type: ApiErrorDto })
  get(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("requestId") requestId: string,
  ): Promise<RoleChangeRequestResponseDto> {
    return this.service.get(user, organizationId, requestId);
  }

  @Post(":requestId/approve")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Approve a role change request",
    description:
      "Approves a pending role change request. Self-approval and target approval are prohibited. " +
      "Enforces configurable independent approval roles and recent-auth assertion token in the " +
      "X-Recent-Auth header when required by policy. Stale membership versions are rejected.",
  })
  @ApiOkResponse({ type: RoleChangeRequestResponseDto })
  @ApiForbiddenResponse({
    description: "Self-approval prohibited, target approval prohibited, or caller lacks approver role.",
    type: ApiErrorDto,
  })
  @ApiConflictResponse({
    description: "Request already terminal, expired, already approved by caller, or stale member revision.",
    type: ApiErrorDto,
  })
  approve(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("requestId") requestId: string,
    @Body() dto: ApproveRoleChangeRequestDto,
    @Req() req: Request,
  ): Promise<RoleChangeRequestResponseDto> {
    const recentAuthToken = String(req.headers["x-recent-auth"] ?? "");
    const origin = String(req.headers["origin"] ?? "null");
    return this.service.approve(user, organizationId, requestId, dto, recentAuthToken, origin);
  }

  @Post(":requestId/reject")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Reject a role change request",
    description:
      "Rejects a pending role change request with a mandatory reason. " +
      "Requires an eligible approver role.",
  })
  @ApiOkResponse({ type: RoleChangeRequestResponseDto })
  @ApiForbiddenResponse({ description: "Caller lacks approver role.", type: ApiErrorDto })
  @ApiConflictResponse({ description: "Request already terminal or expired.", type: ApiErrorDto })
  reject(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("requestId") requestId: string,
    @Body() dto: RejectRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    return this.service.reject(user, organizationId, requestId, dto);
  }

  @Post(":requestId/cancel")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Cancel a role change request",
    description:
      "Cancels a pending role change request. Only the requester, an organization OWNER, " +
      "or a platform ADMIN may cancel.",
  })
  @ApiOkResponse({ type: RoleChangeRequestResponseDto })
  @ApiForbiddenResponse({ description: "Caller is not requester or owner.", type: ApiErrorDto })
  @ApiConflictResponse({ description: "Request already terminal or expired.", type: ApiErrorDto })
  cancel(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("requestId") requestId: string,
    @Body() dto: CancelRoleChangeRequestDto,
  ): Promise<RoleChangeRequestResponseDto> {
    return this.service.cancel(user, organizationId, requestId, dto);
  }
}
