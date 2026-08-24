import { Module } from "@nestjs/common";
import { DatabaseModule } from "../database/database.module";
import { ProofsModule } from "../proofs/proofs.module";
import { IssuersService } from "./issuers.service";
import { IssuersController } from "./issuers.controller";

@Module({
  imports: [DatabaseModule, ProofsModule],
  controllers: [IssuersController],
  providers: [IssuersService],
  exports: [IssuersService],
})
export class IssuersModule {}
