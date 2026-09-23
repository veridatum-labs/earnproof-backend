import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiResponse,
} from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedUser } from "../auth/auth.types";
import { OrganizationMembershipsService } from "./organization-memberships.service";
import { InviteMemberDto } from "./dto/invite-member.dto";
import { UpdateMemberRoleDto } from "./dto/update-member-role.dto";
import { MembershipResponseDto } from "./dto/membership-response.dto";

@ApiBearerAuth()
@ApiTags("organization-memberships")
@Controller("organizations/:organizationId/members")
export class OrganizationMembershipsController {
  constructor(
    private readonly membershipsService: OrganizationMembershipsService,
  ) {}

  @Post()
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "Invite a member to an organization",
    description:
      "Invite a user to join an organization with a specific role. Only OWNER and ADMIN members can invite.",
  })
  @ApiResponse({
    status: 201,
    description: "Member invited successfully",
    type: MembershipResponseDto,
  })
  @ApiResponse({
    status: 409,
    description: "User is already a member of this organization",
  })
  @ApiResponse({
    status: 403,
    description: "Unauthorized - insufficient permissions",
  })
  @ApiResponse({
    status: 404,
    description: "Organization or user not found",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  inviteMember(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Body() input: InviteMemberDto,
  ) {
    return this.membershipsService.inviteMember(user, organizationId, input);
  }

  @Get()
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "List organization members",
    description:
      "List all members of an organization with their roles. Any member can list members.",
  })
  @ApiResponse({
    status: 200,
    description: "Members retrieved successfully",
  })
  @ApiResponse({
    status: 403,
    description: "Unauthorized - not a member of this organization",
  })
  @ApiResponse({
    status: 404,
    description: "Organization not found",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  listMembers(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Query("page") page?: number,
    @Query("limit") limit?: number,
  ) {
    return this.membershipsService.listMembers(user, organizationId, {
      page,
      limit,
    });
  }

  @Patch(":userId")
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "Update member role",
    description:
      "Change a member's role in an organization. Only OWNER and ADMIN members can update roles.",
  })
  @ApiResponse({
    status: 200,
    description: "Member role updated successfully",
    type: MembershipResponseDto,
  })
  @ApiResponse({
    status: 403,
    description:
      "Unauthorized - insufficient permissions or last-owner protection violation",
  })
  @ApiResponse({
    status: 404,
    description: "Organization or member not found",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  updateMemberRole(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("userId") userId: string,
    @Body() input: UpdateMemberRoleDto,
  ) {
    return this.membershipsService.updateMemberRole(
      user,
      organizationId,
      userId,
      input,
    );
  }

  @Delete(":userId")
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "Remove member from organization",
    description:
      "Remove a member from an organization. Only OWNER and ADMIN members can remove members.",
  })
  @ApiResponse({
    status: 200,
    description: "Member removed successfully",
  })
  @ApiResponse({
    status: 403,
    description:
      "Unauthorized - insufficient permissions or last-owner protection violation",
  })
  @ApiResponse({
    status: 404,
    description: "Organization or member not found",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  removeMember(
    @CurrentUser() user: AuthenticatedUser,
    @Param("organizationId") organizationId: string,
    @Param("userId") userId: string,
  ) {
    return this.membershipsService.removeMember(user, organizationId, userId);
  }
}
