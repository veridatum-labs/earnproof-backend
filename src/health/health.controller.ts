import { Controller, Get, HttpStatus } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { HealthResponseDto } from "./dto/health-response.dto";
import { PrismaService } from "../database/prisma.service";

@ApiTags("health")
@Controller("health")
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @ApiOperation({
    summary: "Health check",
    description:
      "Returns the service status and verifies database connectivity by running a lightweight " +
      "`SELECT 1` query. No authentication required.",
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: "Service and database are healthy.",
    type: HealthResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.SERVICE_UNAVAILABLE,
    description: "Database is unreachable.",
    type: ApiErrorDto,
  })
  @Get()
  async getHealth(): Promise<HealthResponseDto> {
    await this.prisma.$queryRaw`SELECT 1`;

    return {
      status: "ok",
      service: "earnproof-api",
      database: "ok",
      timestamp: new Date().toISOString(),
    };
  }
}
