import { ChannelCredentials } from "@grpc/grpc-js";
import { GrpcTransport } from "@protobuf-ts/grpc-transport";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { isValidSuiObjectId, isValidTransactionDigest, normalizeSuiObjectId } from "@mysten/sui/utils";
import type { SuiNetwork } from "@sieve/contracts";

export type TatumSuiConfig = {
  apiKey: string;
  network: SuiNetwork;
  timeoutMs?: number;
};

const transactionReadMask = [
  "digest",
  "checkpoint",
  "timestamp",
  "transaction",
  "effects.status",
  "effects.changed_objects",
  "events.events.json",
  "events.events.event_type",
  "events.events.event_index",
  "events.events.package_id",
  "events.events.module",
  "events.events.sender",
  "objects.objects.json",
  "objects.objects.object_id",
  "objects.objects.object_type",
  "objects.objects.owner",
  "balance_changes",
];

const objectReadMask = [
  "object_id",
  "version",
  "digest",
  "owner",
  "object_type",
  "contents",
  "json",
  "display.output",
  "previous_transaction",
];

export function validateTarget(target: { kind: "transaction"; digest: string } | { kind: "object"; objectId: string }): boolean {
  return target.kind === "transaction"
    ? isValidTransactionDigest(target.digest)
    : isValidSuiObjectId(target.objectId);
}

export function normalizeObjectId(objectId: string): string {
  return normalizeSuiObjectId(objectId);
}

export class TatumSuiClient {
  private readonly network: SuiNetwork;
  private readonly timeoutMs: number;
  private readonly transport: GrpcTransport;
  private readonly client: SuiGrpcClient;

  constructor(config: TatumSuiConfig) {
    this.network = config.network;
    this.timeoutMs = config.timeoutMs ?? 10_000;
    const endpoint = config.network === "mainnet"
      ? "sui-mainnet-grpc.gateway.tatum.io:443"
      : "sui-testnet-grpc.gateway.tatum.io:443";
    this.transport = new GrpcTransport({
      host: endpoint,
      channelCredentials: ChannelCredentials.createSsl(),
      meta: { "x-api-key": config.apiKey },
    });
    this.client = new SuiGrpcClient({ network: config.network, transport: this.transport });
  }

  async checkConnection(): Promise<{ network: SuiNetwork; chainId?: string }> {
    const { response } = await this.client.ledgerService.getServiceInfo({}, { timeout: this.timeoutMs });
    if (response.chain && response.chain !== this.network) {
      throw new Error(`Tatum endpoint returned ${response.chain} while ${this.network} was requested`);
    }
    return response.chainId
      ? { network: this.network, chainId: response.chainId }
      : { network: this.network };
  }

  async getTransaction(digest: string) {
    const { response } = await this.client.ledgerService.getTransaction(
      { digest, readMask: { paths: transactionReadMask } },
      { timeout: this.timeoutMs },
    );
    if (!response.transaction) throw new Error("Tatum returned no transaction for the requested digest");
    return response.transaction;
  }

  async getObject(objectId: string) {
    const { response } = await this.client.ledgerService.getObject(
      { objectId, readMask: { paths: objectReadMask } },
      { timeout: this.timeoutMs },
    );
    if (!response.object) throw new Error("Tatum returned no object for the requested object ID");
    return response.object;
  }

  close(): void {
    this.transport.close();
  }
}
