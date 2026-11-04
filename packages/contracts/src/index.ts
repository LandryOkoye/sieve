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

export type CaseStatus =
  | "queued"
  | "fetching_evidence"
  | "assessing"
  | "completed"
  | "failed";

export type ThreatCategory =
  | "instruction_override"
  | "trust_manipulation"
  | "recommendation_steering"
  | "memory_manipulation";

export type DetectionFinding = {
  category: ThreatCategory;
  signal: string;
  strength: "strong" | "moderate";
  rationale: string;
  evidence: EvidencePointer;
};

export type DetectorVerdict = {
  outcome: "signals_detected" | "no_signals_detected" | "uncertain";
  findings: DetectionFinding[];
  quarantinedText: UntrustedText[];
};

export type InspectionCase = {
  id: string;
  network: SuiNetwork;
  target: LookupTarget;
  status: CaseStatus;
  evidence: EvidenceBundle | null;
  assessment: DetectorVerdict | null;
  failureCode: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ThreatMemoryWriteStatus = "pending" | "accepted" | "uploaded" | "completed" | "failed";

export type ThreatMemoryWrite = {
  id: string;
  caseId: string;
  pattern: string;
  status: ThreatMemoryWriteStatus;
  normalizedRecord: unknown;
  walrusJobId: string | null;
  blobId: string | null;
  failureCode: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ThreatMemoryPage = {
  memories: ThreatMemoryWrite[];
  limit: number;
  nextCursor: string | null;
};
