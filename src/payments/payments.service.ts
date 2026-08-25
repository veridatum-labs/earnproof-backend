import { Injectable, NotFoundException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Payment, PaymentClassification, ResourceStatus } from "@prisma/client";
import { encryptProtectedAmount } from "../common/crypto/protected-amount";
import { PrismaService } from "../database/prisma.service";
import { StellarService } from "../stellar/stellar.service";

@Injectable()
export class PaymentsService {
  private readonly paymentEncryptionKey: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly stellarService: StellarService,
    configService: ConfigService,
  ) {
    this.paymentEncryptionKey = configService.getOrThrow<string>(
      "paymentEncryptionKey",
    );
  }

  async syncPayments(user: { id: string; walletAddress: string }) {
    const incomingPayments = await this.stellarService.fetchIncomingPayments(
      user.walletAddress,
    );
    const supportedAssets = await this.prisma.supportedAsset.findMany({
      where: {
        status: ResourceStatus.ACTIVE,
      },
      select: {
        code: true,
        issuer: true,
        network: true,
      },
    });
    const supportedAssetKeys = new Set(
      supportedAssets.map((asset) => this.assetKey(asset.code, asset.issuer)),
    );

    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const payment of incomingPayments) {
      const isEligible = supportedAssetKeys.has(
        this.assetKey(payment.assetCode, payment.assetIssuer),
      );

      if (!isEligible) {
        skipped += 1;
      }

      const existing = await this.prisma.payment.findUnique({
        where: {
          operationId: payment.operationId,
        },
        select: {
          id: true,
        },
      });

      await this.prisma.payment.upsert({
        where: {
          operationId: payment.operationId,
        },
        update: {
          isEligible,
          occurredAt: payment.occurredAt,
        },
        create: {
          userId: user.id,
          operationId: payment.operationId,
          stellarTransactionHash: payment.stellarTransactionHash,
          sourceAddress: payment.sourceAddress,
          destinationAddress: payment.destinationAddress,
          assetCode: payment.assetCode,
          assetIssuer: payment.assetIssuer,
          amountEncrypted: this.protectAmount(payment.amount),
          occurredAt: payment.occurredAt,
          classification: PaymentClassification.UNKNOWN,
          isEligible,
        },
      });

      if (existing) {
        updated += 1;
      } else {
        created += 1;
      }
    }

    return {
      totalFetched: incomingPayments.length,
      created,
      updated,
      skipped,
    };
  }

  async listPayments(
    userId: string,
    filters: { classification?: PaymentClassification; assetCode?: string },
  ) {
    const payments = await this.prisma.payment.findMany({
      where: {
        userId,
        classification: filters.classification,
        assetCode: filters.assetCode,
      },
      orderBy: {
        occurredAt: "desc",
      },
      take: 100,
    });

    return payments.map((payment) => this.toPaymentResponse(payment));
  }

  async getPayment(userId: string, paymentId: string) {
    const payment = await this.prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId,
      },
    });

    if (!payment) {
      throw new NotFoundException("Payment not found");
    }

    return this.toPaymentResponse(payment);
  }

  async updateClassification(
    user: { id: string },
    paymentId: string,
    classification: PaymentClassification,
  ) {
    const payment = await this.prisma.payment.findFirst({
      where: {
        id: paymentId,
        userId: user.id,
      },
      select: {
        id: true,
        classification: true,
        assetCode: true,
        assetIssuer: true,
        isEligible: true,
      },
    });

    if (!payment) {
      throw new NotFoundException("Payment not found");
    }

    const updated = await this.prisma.payment.update({
      where: {
        id: payment.id,
      },
      data: {
        classification,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: user.id,
        action: "payment.classification.updated",
        resourceType: "payment",
        resourceId: payment.id,
        metadata: {
          previousClassification: payment.classification,
          nextClassification: classification,
          assetCode: payment.assetCode,
          assetIssuer: payment.assetIssuer,
          isEligible: payment.isEligible,
        },
      },
    });

    return this.toPaymentResponse(updated);
  }

  private assetKey(code: string, issuer: string | null) {
    return `${code}:${issuer ?? "native"}`;
  }

  private protectAmount(amount: string) {
    return encryptProtectedAmount(amount, this.paymentEncryptionKey);
  }

  private toPaymentResponse(payment: Payment) {
    return {
      id: payment.id,
      userId: payment.userId,
      stellarTransactionHash: payment.stellarTransactionHash,
      operationId: payment.operationId,
      sourceAddress: payment.sourceAddress,
      destinationAddress: payment.destinationAddress,
      assetCode: payment.assetCode,
      assetIssuer: payment.assetIssuer,
      occurredAt: payment.occurredAt,
      memo: payment.memo,
      classification: payment.classification,
      isEligible: payment.isEligible,
      createdAt: payment.createdAt,
      updatedAt: payment.updatedAt,
    };
  }
}
