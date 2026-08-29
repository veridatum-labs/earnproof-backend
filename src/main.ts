import { ClassSerializerInterceptor, Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { AppModule } from "./app.module";
import { configureApp } from "./bootstrap";
import { ApiErrorDto, FieldViolationDto } from "./common/dto/api-error.dto";
import { HealthService } from "./health/health.service";

async function bootstrap() {
  let app;

  try {
    // ── Configuration validation happens during module initialization ──
    // The validateEnv() hook in AppModule runs immediately, checking both
    // individual field constraints and cross-variable invariants. If validation
    // fails, NestFactory.create() throws and execution never reaches app.listen().
    app = await NestFactory.create(AppModule);
  } catch (error) {
    // ── FAIL FAST: Configuration errors prevent startup entirely ──
    // This ensures the server never listens with bad configuration.
    const logger = new Logger("Bootstrap");
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Configuration validation failed: ${message}`);
    process.exit(1);
  }

  const configService = app.get(ConfigService);
  const port = configService.getOrThrow<number>("port");

  // Body limits, structural limits, security headers, CORS, interceptors, the
  // error filter and validation, in the order a request meets them. See
  // `src/bootstrap.ts`; kept there so tests can exercise the same pipeline.
  configureApp(app, { corsOrigin: configService.getOrThrow<string>("appUrl") });

  // ── Swagger / OpenAPI ────────────────────────────────────────────────────
  const documentConfig = new DocumentBuilder()
    .setTitle("EarnProof API")
    .setDescription(
      "Stellar testnet income proof API.\n\n" +
      "## Error contract\n" +
      "All non-2xx responses use the `ApiErrorDto` envelope:\n" +
      "```json\n" +
      "{\n" +
      '  "statusCode": 401,\n' +
      '  "code": "INVALID_TOKEN",\n' +
      '  "message": "Authentication token is invalid.",\n' +
      '  "requestId": "01hwzxyz..."\n' +
      "}\n" +
      "```\n" +
      "The `code` field is stable across minor versions. Branch on `code`, not `message`.\n\n" +
      "## Request IDs\n" +
      "Pass `X-Request-ID` with any request to correlate logs. " +
      "A generated ID is returned in the `X-Request-ID` response header when none is supplied.",
    )
    .setVersion("0.1.0")
    .addBearerAuth(
      {
        type: "http",
        scheme: "bearer",
        bearerFormat: "Opaque session token",
        description:
          "Bearer token obtained from `POST /api/v1/auth/verify`. " +
          "Include as `Authorization: Bearer <token>`.",
      },
      // The security scheme name must match the argument passed to @ApiBearerAuth()
      // decorators (default is 'bearer' when no name is given).
      "bearer",
    )
    .build();

  const document = SwaggerModule.createDocument(app, documentConfig, {
    // Ensure ApiErrorDto and FieldViolationDto are always included in the
    // generated schema even if they're only referenced via `type` strings.
    extraModels: [ApiErrorDto, FieldViolationDto],
  });

  SwaggerModule.setup("docs", app, document, {
    swaggerOptions: {
      // Persist auth token across page reloads in the Swagger UI.
      persistAuthorization: true,
    },
  });

  // ── Graceful shutdown (earnproof-backend#68) ────────────────────────────
  // enableShutdownHooks() is what makes Nest actually call each provider's
  // onModuleDestroy/onApplicationShutdown on SIGTERM/SIGINT — without it,
  // those lifecycle hooks never fire and the process exits mid-work. See
  // docs/shutdown.md for the full runbook (what each worker drains, how to
  // verify it, how to force-terminate safely).
  app.enableShutdownHooks();

  const shutdownLogger = new Logger("Shutdown");
  const health = app.get(HealthService);

  const shutdown = async (signal: string) => {
    shutdownLogger.log(`Received ${signal} — starting graceful shutdown`);

    // Flip readiness to not_ready FIRST, before Nest's own module-destroy
    // sequence runs, so a load balancer stops routing new traffic here as
    // early in the sequence as possible — new work stops arriving before
    // any draining begins.
    health.beginShutdown();

    try {
      await app.close();
      shutdownLogger.log("Shutdown complete");
      process.exit(0);
    } catch (err) {
      shutdownLogger.error(
        `Shutdown did not complete cleanly: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      process.exit(1);
    }
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  await app.listen(port);
}

void bootstrap();
