import { Body, Controller, Get, Param, Patch, Post, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { AuthenticatedUser } from "../auth/auth.types";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { CreateMinimumIncomeProofDto } from "./dto/create-minimum-income-proof.dto";
import { ProofsService } from "./proofs.service";

@ApiTags("proofs")
@Controller("proofs")
export class ProofsController {
  constructor(private readonly proofsService: ProofsService) {}

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Post("minimum-income")
  createMinimumIncomeProof(
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateMinimumIncomeProofDto,
  ) {
    return this.proofsService.createMinimumIncomeProof(user, body);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Patch(":id/revoke")
  revokeProof(@CurrentUser() user: AuthenticatedUser, @Param("id") id: string) {
    return this.proofsService.revokeProof(user.id, id);
  }

  @Get(":id/verify")
  verifyProof(@Param("id") id: string) {
    return this.proofsService.verifyProof(id);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Get(":id/verification-stats")
  getVerificationStats(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") id: string,
  ) {
    return this.proofsService.getVerificationStats(user.id, id);
  }
}
