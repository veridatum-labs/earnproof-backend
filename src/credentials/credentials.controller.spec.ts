import { BadRequestException, ValidationPipe } from "@nestjs/common";
import { CredentialsController } from "./credentials.controller";
import { CredentialsService, VerifyCredentialResult } from "./credentials.service";
import { VerifyCredentialDto } from "./dto/verify-credential.dto";

/**
 * The controller's own responsibilities, separated from the service's.
 *
 * The service decides whether a credential is genuine, and
 * `credentials.service.spec.ts` covers that. What is left here is small and
 * easy to break silently: unwrapping the request envelope, returning the
 * verdict unchanged, letting a rejection reach the error filter rather than
 * being turned into a verdict, and refusing a submission that is too large or
 * too deep before any of that runs.
 *
 * The validation cases build the same `ValidationPipe` the application does
 * (see `configureApp` in `src/bootstrap.ts`), because a DTO's constraints are
 * only worth as much as the pipe configuration that enforces them.
 */

const validationPipe = new ValidationPipe({
  forbidNonWhitelisted: true,
  transform: true,
  whitelist: true,
});

const metadata = {
  type: "body" as const,
  metatype: VerifyCredentialDto,
};

/** A credential body, valid in shape; the service decides what it is worth. */
function credential() {
  return {
    id: "proof_test_1",
    type: "EarnProofMinimumIncomeCredential",
    schemaVersion: "earnproof.minimum-income.v1",
    proof: { type: "HMAC-SHA256", credentialHash: "sha256:abc", signature: "hmac-sha256:def" },
  };
}

describe("CredentialsController", () => {
  let controller: CredentialsController;
  let service: { verifyCredential: jest.Mock };

  beforeEach(() => {
    service = { verifyCredential: jest.fn() };
    controller = new CredentialsController(
      service as unknown as CredentialsService,
    );
  });

  describe("verifyCredential", () => {
    it("passes the credential itself to the service, not the request envelope", async () => {
      // The DTO wraps the document in a `credential` field. Forwarding the
      // wrapper would make every submission fail its schema check, and the
      // failure would read as a bad credential rather than a bad controller.
      service.verifyCredential.mockResolvedValue({ result: "valid" });

      await controller.verifyCredential({ credential: credential() });

      expect(service.verifyCredential).toHaveBeenCalledTimes(1);
      expect(service.verifyCredential).toHaveBeenCalledWith(credential());
    });

    it.each<VerifyCredentialResult>([
      "valid",
      "invalid_signature",
      "unsupported_schema",
      "unsupported_key",
      "unknown_anchor",
      "revoked",
      "expired",
      "unverified_issuer",
    ])("returns %s unchanged", async (result) => {
      // Every outcome is a successful request. A verdict the controller
      // rewrote, or answered with a different status, would break verifiers
      // that branch on `result`.
      service.verifyCredential.mockResolvedValue({ result });

      await expect(
        controller.verifyCredential({ credential: credential() }),
      ).resolves.toEqual({ result });
    });

    it("propagates a service rejection instead of converting it to a verdict", async () => {
      // A malformed submission is a client error, not a verification outcome.
      // Swallowing it here would answer 200 with a misleading verdict.
      service.verifyCredential.mockRejectedValue(
        new BadRequestException("Credential is malformed"),
      );

      await expect(
        controller.verifyCredential({ credential: credential() }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });
  });

  describe("request validation", () => {
    it("accepts a well-formed submission", async () => {
      await expect(
        validationPipe.transform({ credential: credential() }, metadata),
      ).resolves.toEqual({ credential: credential() });
    });

    it("rejects a missing credential field", async () => {
      await expect(validationPipe.transform({}, metadata)).rejects.toBeInstanceOf(
        BadRequestException,
      );
    });

    it("rejects a credential that is not an object", async () => {
      await expect(
        validationPipe.transform({ credential: "not-an-object" }, metadata),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rejects unknown fields alongside the credential", async () => {
      // forbidNonWhitelisted, so a caller cannot smuggle extra fields past the
      // DTO and have them silently ignored.
      await expect(
        validationPipe.transform(
          { credential: credential(), callbackUrl: "https://example.com" },
          metadata,
        ),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rejects a credential larger than 32 KB", async () => {
      const oversized = { ...credential(), padding: "x".repeat(33 * 1024) };

      await expect(
        validationPipe.transform({ credential: oversized }, metadata),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rejects a credential nested deeper than 5 levels", async () => {
      let nested: Record<string, unknown> = { deepest: true };
      for (let level = 0; level < 8; level += 1) {
        nested = { nested };
      }

      await expect(
        validationPipe.transform({ credential: nested }, metadata),
      ).rejects.toBeInstanceOf(BadRequestException);
    });
  });
});
