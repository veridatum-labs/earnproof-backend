import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { ApiKeyService } from "./api-key.service";
import { ApiKeysController } from "./api-keys.controller";

@Module({
  imports: [AuthModule],
  controllers: [ApiKeysController],
  providers: [ApiKeyService],
  exports: [ApiKeyService],
})
export class ApiKeysModule {}
