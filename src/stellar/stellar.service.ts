import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import {
  HorizonCollection,
  HorizonPaymentRecord,
  NormalizedPayment,
} from "./stellar.types";

@Injectable()
export class StellarService {
  private readonly horizonUrl: string;

  constructor(configService: ConfigService) {
    this.horizonUrl = configService
      .getOrThrow<string>("stellar.horizonUrl")
      .replace(/\/$/, "");
  }

  async fetchIncomingPayments(walletAddress: string): Promise<NormalizedPayment[]> {
    let response: Response;
    try {
      response = await fetch(
        `${this.horizonUrl}/accounts/${walletAddress}/payments?limit=200&order=desc`,
      );
    } catch {
      throw new ServiceUnavailableException(
        "Stellar Horizon is temporarily unavailable",
      );
    }

    if (!response.ok) {
      throw new ServiceUnavailableException(
        "Stellar Horizon is temporarily unavailable",
      );
    }

    const data =
      (await response.json()) as HorizonCollection<HorizonPaymentRecord>;
    const records = data._embedded?.records ?? [];

    return records
      .filter((record) => record.type === "payment")
      .filter((record) => record.to === walletAddress)
      .filter((record) => Boolean(record.from && record.amount))
      .map((record) => this.normalizePayment(record));
  }

  private normalizePayment(record: HorizonPaymentRecord): NormalizedPayment {
    const isNative = record.asset_type === "native";

    return {
      operationId: record.id,
      stellarTransactionHash: record.transaction_hash,
      sourceAddress: record.from as string,
      destinationAddress: record.to as string,
      assetCode: isNative ? "XLM" : (record.asset_code as string),
      assetIssuer: isNative ? null : (record.asset_issuer ?? null),
      amount: record.amount as string,
      occurredAt: new Date(record.created_at),
    };
  }
}
