import {
  ArgumentsHost,
  BadRequestException,
  InternalServerErrorException,
  UnauthorizedException,
} from "@nestjs/common";
import { GlobalExceptionFilter } from "../../src/common/filters/global-exception.filter";
import { ApiErrorCode } from "../../src/common/dto/api-error.dto";
import { redact } from "../../src/common/observability/redaction";

/**
 * Sentinel-based integration scanner for PII leakage (#440).
 *
 * Scans rendered logs and HTTP error responses across critical failure paths:
 * auth, payment, proof, issuer, API-key, and webhook flows.
 *
 * Asserts that:
 * 1. Sentinel wallet, token, memo, signature, and amount values never appear.
 * 2. Safe correlation identifiers (requestId) remain available and uncorrupted.
 * 3. Both structured (JSON body) and plain-text (logger) outputs are covered.
 * 4. Emitting failure path is identified by status/code without echoing secrets.
 */

describe("PII Leakage Sentinel Scanner (Integration)", () => {
  let filter: GlobalExceptionFilter;
  let loggedErrors: string[];
  let loggedWarns: string[];

  const SENTINELS = {
    wallet: "GSENTINELWALLET9876543210ABCDEFGHIJKLMNOPQRSTUV123456",
    secretSeed: "SSENTINELSEED9876543210ABCDEFGHIJKLMNOPQRSTUV123456",
    token: "ep_live_sentinel_secret_api_key_999888777",
    sessionToken: "sentineltokenabc.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    memo: "sentinel-memo-payroll-confidential-user-42",
    signature: "sentinel-signature-0123456789abcdef0123456789abcdef0123456789abcdef",
    amount: "99999.99 XLM",
    encryptedAmount: "enc:v1:sentinelPayload:sentinelTag:sentinelIv",
  };

  const ALL_SENTINELS = Object.values(SENTINELS);

  function makeTestHost(requestId = "test-corr-id-1234") {
    const jsonMock = jest.fn();
    const setHeaderMock = jest.fn();
    const statusMock = jest.fn().mockReturnValue({ json: jsonMock });

    const request = {
      requestId,
      headers: { "x-request-id": requestId },
    };

    const host = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ status: statusMock, setHeader: setHeaderMock }),
      }),
    } as unknown as ArgumentsHost;

    return { host, jsonMock, statusMock, setHeaderMock, requestId };
  }

  function assertNoSentinelsLeak(target: string | object, contextDesc: string) {
    const text = typeof target === "string" ? target : JSON.stringify(target);
    for (const sentinel of ALL_SENTINELS) {
      expect(text).not.toContain(sentinel);
    }
  }

  beforeEach(() => {
    filter = new GlobalExceptionFilter();
    loggedErrors = [];
    loggedWarns = [];

    jest.spyOn(filter["logger"], "error").mockImplementation((msg, stack) => {
      loggedErrors.push(`${msg} ${stack || ""}`);
    });
    jest.spyOn(filter["logger"], "warn").mockImplementation((msg) => {
      loggedWarns.push(String(msg));
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("Critical Failure Paths Sentinel Scan", () => {
    it("1. Auth failure path: rejects invalid token without echoing sentinel bearer/session token", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const authError = new UnauthorizedException(
        `Failed authentication with token: ${SENTINELS.token} session: ${SENTINELS.sessionToken}`,
      );

      filter.catch(authError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);
      expect(responseBody.code).toBeDefined();

      assertNoSentinelsLeak(responseBody, "Auth HTTP response body");
      assertNoSentinelsLeak(loggedWarns.join(" "), "Auth warning logs");
      assertNoSentinelsLeak(loggedErrors.join(" "), "Auth error logs");
    });

    it("2. Payment failure path: sanitizes wallet address, amount, and memo in validation and execution errors", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const paymentError = new BadRequestException({
        statusCode: 400,
        message: [
          `destinationAddress ${SENTINELS.wallet} is not a valid recipient`,
          `amount ${SENTINELS.amount} exceeds balance limit`,
          `memo contains invalid format memo: ${SENTINELS.memo}`,
        ],
        error: "Bad Request",
      });

      filter.catch(paymentError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);
      expect(responseBody.code).toBe(ApiErrorCode.VALIDATION_ERROR);
      expect(responseBody.violations).toBeDefined();

      assertNoSentinelsLeak(responseBody, "Payment HTTP response body");
      assertNoSentinelsLeak(loggedWarns.join(" "), "Payment warning logs");
    });

    it("3. Proof failure path: rejects invalid proof without echoing sentinel signature or encrypted commitment", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const proofError = new BadRequestException(
        `Verification failed for signature: ${SENTINELS.signature} with amount: ${SENTINELS.encryptedAmount}`,
      );

      filter.catch(proofError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);

      assertNoSentinelsLeak(responseBody, "Proof HTTP response body");
      assertNoSentinelsLeak(loggedWarns.join(" "), "Proof warning logs");
    });

    it("4. Issuer failure path: masks secret seeds and signing keys in internal server exceptions", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const internalError = new InternalServerErrorException(
        `Failed to rotate issuer key using seed ${SENTINELS.secretSeed}`,
      );

      filter.catch(internalError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);
      expect(responseBody.statusCode).toBe(500);

      assertNoSentinelsLeak(responseBody, "Issuer HTTP response body");
      assertNoSentinelsLeak(loggedErrors.join(" "), "Issuer error logs and stack");
    });

    it("5. API-key failure path: rejects invalid API key without leaking the key to logs or clients", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const apiKeyError = new UnauthorizedException(
        `Invalid API key provided: ${SENTINELS.token}`,
      );

      filter.catch(apiKeyError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);

      assertNoSentinelsLeak(responseBody, "API-key HTTP response body");
      assertNoSentinelsLeak(loggedWarns.join(" "), "API-key warning logs");
    });

    it("6. Webhook failure path: prevents leakage of webhook secret or signed payload", () => {
      const { host, jsonMock, requestId } = makeTestHost();
      const webhookSecret = "whsec_sentinel_webhook_secret_key_12345";
      const webhookError = new BadRequestException(
        `Webhook signature mismatch for secret ${webhookSecret} on signature ${SENTINELS.signature}`,
      );

      filter.catch(webhookError, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(requestId);

      assertNoSentinelsLeak(responseBody, "Webhook HTTP response body");
      assertNoSentinelsLeak(loggedWarns.join(" "), "Webhook warning logs");
      expect(JSON.stringify(responseBody)).not.toContain(webhookSecret);
    });
  });

  describe("Safe Correlation and Path Identification", () => {
    it("preserves safe correlation identifiers across all failure responses", () => {
      const customRequestId = "safe-corr-uuid-777-888";
      const { host, jsonMock, setHeaderMock } = makeTestHost(customRequestId);

      filter.catch(new BadRequestException("Safe error message"), host);

      expect(setHeaderMock).toHaveBeenCalledWith("x-request-id", customRequestId);
      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.requestId).toBe(customRequestId);
    });

    it("identifies the emitting failure path cleanly without echoing secrets", () => {
      const { host, jsonMock } = makeTestHost();
      const errorWithSecret = new UnauthorizedException(
        `Unauthorized access attempt with ${SENTINELS.token}`,
      );

      filter.catch(errorWithSecret, host);

      const responseBody = jsonMock.mock.calls[0][0];
      expect(responseBody.statusCode).toBe(401);
      expect(responseBody.message).toContain("[REDACTED");
      expect(responseBody.message).not.toContain(SENTINELS.token);
    });
  });
});
