import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { AppModule } from "./app.module";
import { configureApp } from "./bootstrap";
import { ApiErrorDto, FieldViolationDto } from "./common/dto/api-error.dto";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
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

  await app.listen(port);
}

void bootstrap();
