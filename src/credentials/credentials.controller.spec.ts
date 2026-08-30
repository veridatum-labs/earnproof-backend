import { BadRequestException, INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { configureApp } from "../bootstrap";
import { CredentialsController } from "./credentials.controller";
import { CredentialsService } from "./credentials.service";
import { listen, postJson } from "../../test/security/http-client";

/**
 * HTTP-level tests for CredentialsController (#108).
 *
 * The app is built with the real `configureApp` pipeline (the same one
 * `main.ts` uses) so these tests exercise the real global prefix, the real
 * ValidationPipe, and the real GlobalExceptionFilter error envelope — not a
 * hand-rolled stand-in that could silently diverge from production. Only
 * `CredentialsService` is mocked, since the service's own behavior already
 * has full unit coverage in credentials.service.spec.ts.
 */
describe("CredentialsController (HTTP)", () => {
  let app: INestApplication;
  let baseUrl: string;
  let credentialsService: { verifyCredential: jest.Mock };

  beforeAll(async () => {
    credentialsService = { verifyCredential: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      controllers: [CredentialsController],
      providers: [
        { provide: CredentialsService, useValue: credentialsService },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    configureApp(app);
    await app.init();
    baseUrl = await listen(app);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    credentialsService.verifyCredential.mockReset();
  });

  describe("POST /credentials/verify", () => {
    it("returns 200 with the service's verification result for a well-formed request", async () => {
      credentialsService.verifyCredential.mockResolvedValue({
        result: "valid",
      });

      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: { id: "cred_1", type: "EarnProofMinimumIncomeCredential" },
      });

      expect(res.status).toBe(200);
      expect(res.json).toEqual({ result: "valid" });
      expect(credentialsService.verifyCredential).toHaveBeenCalledWith({
        id: "cred_1",
        type: "EarnProofMinimumIncomeCredential",
      });
    });

    it("passes through whatever result the service returns (e.g. revoked)", async () => {
      credentialsService.verifyCredential.mockResolvedValue({
        result: "revoked",
      });

      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: { id: "cred_1" },
      });

      expect(res.status).toBe(200);
      expect(res.json).toEqual({ result: "revoked" });
    });

    it("returns 422 (DTO validation error) when `credential` is missing", async () => {
      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {});

      expect(res.status).toBe(422);
      expect(res.json?.code).toBe("VALIDATION_ERROR");
      expect(credentialsService.verifyCredential).not.toHaveBeenCalled();
    });

    it("returns 422 when `credential` is not an object", async () => {
      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: "not-an-object",
      });

      expect(res.status).toBe(422);
      expect(res.json?.code).toBe("VALIDATION_ERROR");
    });

    it("returns 422 when the request body has an unrecognized top-level field (whitelist rejection)", async () => {
      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: { id: "cred_1" },
        extraField: "should not be allowed",
      });

      expect(res.status).toBe(422);
      expect(credentialsService.verifyCredential).not.toHaveBeenCalled();
    });

    it("returns 422 when the credential object exceeds the DTO's byte-size limit (but stays under the route's transport limit and the shape middleware's per-string limit)", async () => {
      // VerifyCredentialDto caps `credential` at 32 KB; the route's own
      // transport-level body limit is 40 KB, and the structural shape
      // middleware separately caps any single string at 8 KB (see
      // request-limits.ts). A single oversized string trips that 8 KB
      // structural check (413) before ever reaching DTO validation — so the
      // size here is spread across several fields, each under 8 KB, so the
      // *object's total* exceeds 32 KB without any individual string or the
      // whole request tripping an earlier limit.
      const chunk = "x".repeat(7 * 1024); // under the 8 KB per-string cap
      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: {
          id: "cred_1",
          field1: chunk,
          field2: chunk,
          field3: chunk,
          field4: chunk,
          field5: chunk,
        },
      });

      expect(res.status).toBe(422);
      expect(credentialsService.verifyCredential).not.toHaveBeenCalled();
    });

    it("returns 422 when the credential object is nested deeper than the allowed depth", async () => {
      let nested: Record<string, unknown> = { leaf: true };
      for (let i = 0; i < 10; i++) {
        nested = { child: nested };
      }

      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: nested,
      });

      expect(res.status).toBe(422);
      expect(credentialsService.verifyCredential).not.toHaveBeenCalled();
    });

    it("has no authentication requirement — a request with no Authorization header still reaches the service", async () => {
      credentialsService.verifyCredential.mockResolvedValue({
        result: "valid",
      });

      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: { id: "cred_1" },
      });

      expect(res.status).toBe(200);
      expect(credentialsService.verifyCredential).toHaveBeenCalled();
    });

    it("propagates a thrown BadRequestException from the service as a 400 with the real error envelope", async () => {
      credentialsService.verifyCredential.mockImplementation(() => {
        throw new BadRequestException("Malformed credential");
      });

      const res = await postJson(baseUrl, "/api/v1/credentials/verify", {
        credential: { id: "cred_1" },
      });

      expect(res.status).toBe(400);
      expect(res.json).toMatchObject({
        code: "INVALID_INPUT",
        requestId: expect.any(String),
      });
    });
  });
});
