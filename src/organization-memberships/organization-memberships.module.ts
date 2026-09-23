import { Module } from "@nestjs/common";
import { AuthModule } from "../auth/auth.module";
import { DatabaseModule } from "../database/database.module";
import { OrganizationMembershipsService } from "./organization-memberships.service";
import { OrganizationMembershipsController } from "./organization-memberships.controller";

@Module({
  imports: [DatabaseModule, AuthModule],
  controllers: [OrganizationMembershipsController],
  providers: [OrganizationMembershipsService],
  exports: [OrganizationMembershipsService],
})
export class OrganizationMembershipsModule {}
