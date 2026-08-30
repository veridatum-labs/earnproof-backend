import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from "@nestjs/common";
import { ApiBearerAuth, ApiTags } from "@nestjs/swagger";
import { SkipThrottle, Throttle } from "@nestjs/throttler";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { AuthenticatedUser } from "../auth/auth.types";
import { ListPaymentsDto } from "./dto/list-payments.dto";
import { UpdatePaymentClassificationDto } from "./dto/update-payment-classification.dto";
import { PaymentsService } from "./payments.service";

@ApiBearerAuth()
@ApiTags("payments")
@UseGuards(AuthGuard)
@Controller("payments")
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  // Payment sync hits Stellar Horizon and writes a batch of records — the
  // other "expensive operation" the issue calls out alongside proof
  // creation. Same "strict" tier, same SkipThrottle reasoning as
  // ProofsController.createMinimumIncomeProof.
  @SkipThrottle({ default: true, verification: true })
  @Throttle({ strict: {} })
  @Post("sync")
  syncPayments(@CurrentUser() user: AuthenticatedUser) {
    return this.paymentsService.syncPayments(user);
  }

  @Get()
  listPayments(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListPaymentsDto,
  ) {
    return this.paymentsService.listPayments(user.id, query);
  }

  @Get(":id")
  getPayment(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
  ) {
    return this.paymentsService.getPayment(user.id, paymentId);
  }

  @Patch(":id/classification")
  updateClassification(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") paymentId: string,
    @Body() body: UpdatePaymentClassificationDto,
  ) {
    return this.paymentsService.updateClassification(
      user,
      paymentId,
      body.classification,
    );
  }
}
