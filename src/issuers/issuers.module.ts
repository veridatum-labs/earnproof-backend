import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { DatabaseModule } from "../database/database.module";
import { ProofsModule } from "../proofs/proofs.module";
import { IssuersService } from "./issuers.service";
import { IssuersController } from "./issuers.controller";

@Module({
  imports: [DatabaseModule, ProofsModule, AuthModule],
  controllers: [IssuersController],
  providers: [IssuersService],
  exports: [IssuersService],
})
export class IssuersModule {}
