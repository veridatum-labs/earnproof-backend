import SwaggerParser from "@apidevtools/swagger-parser";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { ApiErrorDto, FieldViolationDto } from "./common/dto/api-error.dto";

describe("generated OpenAPI document", () => {
  const originalEnv = process.env;
  let app: INestApplication;

  beforeAll(async () => {
    process.env = {
      ...originalEnv,
      APP_URL: "http://localhost:3000",
      API_URL: "http://localhost:4000",
      CREDENTIAL_SIGNING_SECRET: "credential_secret_123",
      DATABASE_URL: "postgresql://user:password@localhost:5432/earnproof",
      PAYMENT_ENCRYPTION_KEY: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
      REDIS_URL: "redis://localhost:6379",
      SESSION_SECRET: "session_secret_123",
      STELLAR_HORIZON_URL: "https://horizon-testnet.stellar.org",
      STELLAR_NETWORK: "testnet",
      STELLAR_NETWORK_PASSPHRASE: "Test SDF Network ; September 2015",
    };
    const { AppModule } = await import("./app.module");
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix("api/v1");
  });

  afterAll(async () => {
    await app.close();
    process.env = originalEnv;
  });

  it("passes schema validation and documents every endpoint", async () => {
    const config = new DocumentBuilder()
      .setTitle("EarnProof API")
      .setVersion("0.1.0")
      .addBearerAuth(
        { type: "http", scheme: "bearer", bearerFormat: "token" },
        "bearer",
      )
      .build();
    const document = SwaggerModule.createDocument(app, config, {
      extraModels: [ApiErrorDto, FieldViolationDto],
    });

    await expect(
      SwaggerParser.validate(document as never),
    ).resolves.toBeDefined();
    expect(document.paths).toHaveProperty(
      "/api/v1/proofs/{id}/verification-stats.get",
    );
    expect(document.paths).toHaveProperty("/api/v1/proofs.get");
    expect(document.paths).toHaveProperty("/api/v1/proofs/{id}.get");
    expect(document.paths).toHaveProperty("/api/v1/payments.get");
    expect(document.paths).toHaveProperty("/api/v1/auth/verify.post");
  });
});
