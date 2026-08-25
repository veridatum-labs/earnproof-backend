import { BadRequestException, Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ProofStatus } from "@prisma/client";
import { createHmac } from "crypto";
import { z } from "zod";
import { canonicalize } from "../common/crypto/canonicalize";
import { sha256 } from "../common/crypto/hash";
import { safeEqual } from "../common/crypto/timing-safe";
import { PrismaService } from "../database/prisma.service";

const MAX_PAYLOAD_BYTES = 32 * 1024; // 32 KB
const MAX_DEPTH = 5;
const SUPPORTED_SCHEMA_VERSION = "earnproof.minimum-income.v1";
const SUPPORTED_TYPE = "EarnProofMinimumIncomeCredential";

// ---------------------------------------------------------------------------
// Response type
// ---------------------------------------------------------------------------

export type VerifyCredentialResult =
  | "valid"
  | "invalid_signature"
  | "unsupported_schema"
  | "unknown_anchor"
  | "revoked"
  | "expired"
  | "unverified_issuer";

export interface VerifyCredentialResponse {
  result: VerifyCredentialResult;
}

// ---------------------------------------------------------------------------
// Zod schema for minimum-income credential shape
// ---------------------------------------------------------------------------

const MinimumIncomeCredentialSchema = z.object({
  id: z.string().min(1),
  type: z.literal(SUPPORTED_TYPE),
  schemaVersion: z.literal(SUPPORTED_SCHEMA_VERSION),
  issuer: z.string().min(1),
  subject: z.object({
    walletHash: z.string().min(1),
  }),
  claim: z.object({
    operator: z.string().min(1),
    thresholdAmount: z.string().min(1),
    assetCode: z.string().min(1),
    assetIssuer: z.string().nullable(),
    periodStart: z.string().min(1),
    periodEnd: z.string().min(1),
    qualifyingPaymentCount: z.number().int().nonnegative(),
  }),
  privacy: z.object({
    exactIncomeHidden: z.literal(true),
    sourceTransactionsHidden: z.literal(true),
  }),
  issuedAt: z.string().min(1),
  expiresAt: z.string().min(1),
  // The signature proof block appended when a credential is issued
  proof: z.object({
    type: z.string().min(1),
    credentialHash: z.string().min(1),
    signature: z.string().min(1),
  }),
});

type MinimumIncomeCredential = z.infer<typeof MinimumIncomeCredentialSchema>;

// ---------------------------------------------------------------------------
// Depth helper (mirrors the one in the DTO for symmetry)
// ---------------------------------------------------------------------------

function objectDepth(value: unknown, current = 0): number {
  if (value === null || typeof value !== "object") {
    return current;
  }
  const children = Array.isArray(value)
    ? value
    : Object.values(value as Record<string, unknown>);
  if (children.length === 0) return current + 1;
  return Math.max(...children.map((child) => objectDepth(child, current + 1)));
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

@Injectable()
export class CredentialsService {
  private readonly logger = new Logger(CredentialsService.name);
  private readonly signingSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    configService: ConfigService,
  ) {
    this.signingSecret = configService.getOrThrow<string>(
      "credentialSigningSecret",
    );
  }

  async verifyCredential(
    raw: Record<string, unknown>,
  ): Promise<VerifyCredentialResponse> {
    // ------------------------------------------------------------------
    // 1. Size / depth guard
    // ------------------------------------------------------------------
    const payloadBytes = Buffer.byteLength(JSON.stringify(raw), "utf8");
    if (payloadBytes > MAX_PAYLOAD_BYTES) {
      throw new BadRequestException(
        `Credential payload must not exceed ${MAX_PAYLOAD_BYTES / 1024} KB`,
      );
    }

    if (objectDepth(raw) > MAX_DEPTH) {
      throw new BadRequestException(
        `Credential payload must not be nested deeper than ${MAX_DEPTH} levels`,
      );
    }

    // ------------------------------------------------------------------
    // 2. Schema / type check (fast early-exit, before any heavy work)
    // ------------------------------------------------------------------
    if (
      raw["schemaVersion"] !== SUPPORTED_SCHEMA_VERSION ||
      raw["type"] !== SUPPORTED_TYPE
    ) {
      return { result: "unsupported_schema" };
    }

    // ------------------------------------------------------------------
    // 3. Shape validation via Zod
    // ------------------------------------------------------------------
    const parsed = MinimumIncomeCredentialSchema.safeParse(raw);
    if (!parsed.success) {
      throw new BadRequestException(
        `Credential is malformed: ${parsed.error.issues
          .map((i) => `${i.path.join(".")}: ${i.message}`)
          .join("; ")}`,
      );
    }

    const credential: MinimumIncomeCredential = parsed.data;

    // ------------------------------------------------------------------
    // 4. Canonicalize the credential body (exclude the proof block) and
    //    compute credentialHash
    // ------------------------------------------------------------------
    const { proof, ...credentialBody } = credential;
    const canonicalPayload = canonicalize(credentialBody);
    const credentialHash = `sha256:${sha256(canonicalPayload)}`;

    // ------------------------------------------------------------------
    // 5. Signature check — recompute HMAC and compare timing-safely
    // ------------------------------------------------------------------
    const expectedSignature = `hmac-sha256:${createHmac("sha256", this.signingSecret)
      .update(canonicalPayload)
      .digest("base64url")}`;

    if (!safeEqual(expectedSignature, proof.signature)) {
      this.logger.log({
        event: "credential_verify",
        result: "invalid_signature",
        credentialHash,
      });
      return { result: "invalid_signature" };
    }

    // ------------------------------------------------------------------
    // 6. Database reconciliation
    // ------------------------------------------------------------------
    const record = await this.prisma.proof.findUnique({
      where: { credentialHash },
      select: {
        status: true,
        expiresAt: true,
        schemaVersion: true,
      },
    });

    if (!record) {
      this.logger.log({
        event: "credential_verify",
        result: "unknown_anchor",
        credentialHash,
      });
      return { result: "unknown_anchor" };
    }

    if (record.status === ProofStatus.REVOKED) {
      this.logger.log({
        event: "credential_verify",
        result: "revoked",
        credentialHash,
      });
      return { result: "revoked" };
    }

    if (record.expiresAt <= new Date()) {
      this.logger.log({
        event: "credential_verify",
        result: "expired",
        credentialHash,
      });
      return { result: "expired" };
    }

    if (record.status !== ProofStatus.ACTIVE) {
      this.logger.log({
        event: "credential_verify",
        result: "unverified_issuer",
        credentialHash,
      });
      return { result: "unverified_issuer" };
    }

    // ------------------------------------------------------------------
    // 7. All checks passed
    // ------------------------------------------------------------------
    this.logger.log({
      event: "credential_verify",
      result: "valid",
      credentialHash,
    });
    return { result: "valid" };
  }
}
