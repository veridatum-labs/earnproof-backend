import { Body, Controller, Get, Param, Patch, Post, UseGuards } from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { SkipThrottle, Throttle } from "@nestjs/throttler";
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
  // Proof creation is expensive (Stellar reads, contract anchoring) — the
  // "strict" tier, not "default". SkipThrottle excludes the OTHER named
  // throttlers so this route is judged against exactly one budget, not all
  // three simultaneously (see rate-limit.module.ts's doc comment).
  @SkipThrottle({ default: true, verification: true })
  @Throttle({ strict: {} })
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

  // The public, unauthenticated verification lookup — the endpoint the
  // issue specifically calls out as needing abuse protection. Its own
  // "verification" tier, separate from "default" so a legitimate app
  // polling verification status isn't squeezed by unrelated traffic on
  // other public routes, and separate from "strict" since a read-only
  // lookup isn't as expensive as proof creation.
  @SkipThrottle({ default: true, strict: true })
  @Throttle({ verification: {} })
  @Get(":id/verify")
  verifyProof(@Param("id") id: string) {
    return this.proofsService.verifyProof(id);
  }
}
