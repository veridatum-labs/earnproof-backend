import { Global, Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";
import { MigrationLeaseService } from "./migration-lease.service";
import { DistributedLeaseService } from "../jobs/distributed-lease.service";
import { DatabaseMaintenanceService } from "./database-maintenance.service";

@Global()
@Module({
  providers: [
    PrismaService,
    MigrationLeaseService,
    DistributedLeaseService,
    DatabaseMaintenanceService,
  ],
  exports: [
    PrismaService,
    MigrationLeaseService,
    DistributedLeaseService,
    DatabaseMaintenanceService,
  ],
})
export class DatabaseModule {}
