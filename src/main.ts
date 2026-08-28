import { ClassSerializerInterceptor, Logger, ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NestFactory, Reflector } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import helmet from "helmet";
import { AppModule } from "./app.module";
import { GlobalExceptionFilter } from "./common/filters/global-exception.filter";
import { RequestIdInterceptor } from "./common/interceptors/request-id.interceptor";
import { ApiErrorDto, FieldViolationDto } from "./common/dto/api-error.dto";
import { HealthService } from "./health/health.service";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.getOrThrow<number>("port");

  app.setGlobalPrefix("api/v1");
  app.use(helmet());
  app.enableCors({
    origin: configService.getOrThrow<string>("appUrl"),
    credentials: true,
    exposedHeaders: ["x-request-id"],
  });

  // ── Request-ID interceptor (must run before the exception filter so that
  //    req.requestId is populated when an error is thrown by a guard or pipe).
  app.useGlobalInterceptors(
    new RequestIdInterceptor(),
    new ClassSerializerInterceptor(app.get(Reflector)),
  );

  // ── Global exception filter — converts every thrown error to ApiErrorDto.
  //    Registered after interceptors so it can read req.requestId.
  app.useGlobalFilters(new GlobalExceptionFilter());

  // ── Validation pipe — forbids unknown fields, enables implicit type coercion.
  app.useGlobalPipes(
    new ValidationPipe({
      forbidNonWhitelisted: true,
      transform: true,
      whitelist: true,
    }),
  );

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
