export type SuiNetwork = "mainnet" | "testnet";

export type LookupTarget =
  | { kind: "transaction"; digest: string }
  | { kind: "object"; objectId: string };

export type EvidencePointer = {
  digest?: string;
  objectId?: string;
  eventIndex?: number;
};

export type ChainFact = {
  field: string;
  value: string | number | boolean | null;
  evidence: EvidencePointer;
};

export type UntrustedText = {
  field: string;
  value: string;
  evidence: EvidencePointer;
};

export type EvidenceBundle = {
  network: SuiNetwork;
  target: LookupTarget;
  retrievedAt: string;
  provider: "tatum-sui-grpc";
  providerMethod: string;
  completeness: "complete" | "partial";
  facts: ChainFact[];
  untrustedText: UntrustedText[];
  warnings: string[];
};
