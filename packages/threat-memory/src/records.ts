export type ThreatMemoryScope =
  | { kind: "agent"; workspaceId: string; agentId: string }
  | { kind: "workspace"; workspaceId: string }
  | { kind: "global" };

export type ThreatMemoryStatus =
  | "candidate"
  | "validated"
  | "active"
  | "superseded"
  | "revoked"
  | "rejected"
  | "false_positive";

export type ThreatMemoryValidation = {
  reviewerId: string;
  reviewedAt: string;
  rationale: string;
  privacyReviewed: boolean;
  corroboratingWorkspaceIds: string[];
};

export type ThreatMemory = {
  id: string;
  schemaVersion: 1;
  scope: ThreatMemoryScope;
  category: string;
  techniqueId: string;
  summary: string;
  behavioralFeatures: string[];
  safeFingerprint: string;
  sourceType: string;
  evidenceHashes: string[];
  confidence: number;
  confidenceRationale: string;
  status: ThreatMemoryStatus;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  validation: ThreatMemoryValidation | null;
};


export type MemoryRecallScope = { workspaceId: string; agentId: string; includeGlobal: boolean };

const statuses = new Set<ThreatMemoryStatus>([
  "candidate", "validated", "active", "superseded", "revoked", "rejected", "false_positive",
]);
const hashPattern = /^[a-f0-9]{64}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

export function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function parseScope(value: unknown): ThreatMemoryScope | null {
  if (!isRecord(value) || typeof value.kind !== "string") return null;
  if (value.kind === "global" && onlyKeys(value, ["kind"])) return { kind: "global" };
  if (value.kind === "workspace" && onlyKeys(value, ["kind", "workspaceId"]) && typeof value.workspaceId === "string" && value.workspaceId.length > 0) {
    return { kind: "workspace", workspaceId: value.workspaceId };
  }
  if (value.kind === "agent" && onlyKeys(value, ["kind", "workspaceId", "agentId"]) &&
      typeof value.workspaceId === "string" && value.workspaceId.length > 0 &&
      typeof value.agentId === "string" && value.agentId.length > 0) {
    return { kind: "agent", workspaceId: value.workspaceId, agentId: value.agentId };
  }
  return null;
}

/** Strictly parse the minimized record returned by Walrus; unknown fields are rejected. */
export function parseThreatMemory(value: unknown): ThreatMemory | null {
  const keys = [
    "id", "schemaVersion", "scope", "category", "techniqueId", "summary", "behavioralFeatures",
    "safeFingerprint", "sourceType", "evidenceHashes", "confidence", "confidenceRationale", "status",
    "createdBy", "createdAt", "updatedAt", "expiresAt", "validation",
  ];
  if (!isRecord(value) || !onlyKeys(value, keys)) return null;
  const scope = parseScope(value.scope);
  if (!scope || value.schemaVersion !== 1 || typeof value.id !== "string" || !value.id ||
      typeof value.category !== "string" || !/^[a-z][a-z0-9_]{1,79}$/.test(value.category) ||
      typeof value.techniqueId !== "string" || value.techniqueId.length < 2 || value.techniqueId.length > 100 ||
      typeof value.summary !== "string" || !value.summary.trim() || value.summary.length > 300 ||
      typeof value.sourceType !== "string" || !value.sourceType.trim() || value.sourceType.length > 80 ||
      typeof value.confidenceRationale !== "string" || !value.confidenceRationale.trim() || value.confidenceRationale.length > 300 ||
      typeof value.confidence !== "number" || !Number.isFinite(value.confidence) || value.confidence < 0 || value.confidence > 1 ||
      typeof value.createdBy !== "string" || !value.createdBy ||
      !isIsoDate(value.createdAt) || !isIsoDate(value.updatedAt) ||
      (value.expiresAt !== null && !isIsoDate(value.expiresAt)) ||
      typeof value.safeFingerprint !== "string" || !hashPattern.test(value.safeFingerprint) ||
      !Array.isArray(value.behavioralFeatures) || value.behavioralFeatures.length < 1 || value.behavioralFeatures.length > 12 ||
      value.behavioralFeatures.some((feature) => typeof feature !== "string" || !feature.trim() || feature.length > 120) ||
      !Array.isArray(value.evidenceHashes) || value.evidenceHashes.length < 1 || value.evidenceHashes.length > 20 ||
      value.evidenceHashes.some((hash) => typeof hash !== "string" || !hashPattern.test(hash)) ||
      typeof value.status !== "string" || !statuses.has(value.status as ThreatMemoryStatus)) {
    return null;
  }

  let validation: ThreatMemoryValidation | null = null;
  if (value.validation !== null) {
    const raw = value.validation;
    if (!isRecord(raw) || !onlyKeys(raw, ["reviewerId", "reviewedAt", "rationale", "privacyReviewed", "corroboratingWorkspaceIds"]) ||
        typeof raw.reviewerId !== "string" || !raw.reviewerId || !isIsoDate(raw.reviewedAt) ||
        typeof raw.rationale !== "string" || raw.rationale.trim().length < 12 || raw.rationale.length > 500 ||
        typeof raw.privacyReviewed !== "boolean" || !Array.isArray(raw.corroboratingWorkspaceIds) ||
        raw.corroboratingWorkspaceIds.some((id) => typeof id !== "string" || !id)) {
      return null;
    }
    validation = {
      reviewerId: raw.reviewerId,
      reviewedAt: raw.reviewedAt,
      rationale: raw.rationale,
      privacyReviewed: raw.privacyReviewed,
      corroboratingWorkspaceIds: [...new Set(raw.corroboratingWorkspaceIds as string[])],
    };
  }

  if ((value.status === "validated" || value.status === "active") !== (validation !== null)) return null;
  return {
    id: value.id,
    schemaVersion: 1,
    scope,
    category: value.category,
    techniqueId: value.techniqueId,
    summary: value.summary,
    behavioralFeatures: [...value.behavioralFeatures] as string[],
    safeFingerprint: value.safeFingerprint,
    sourceType: value.sourceType,
    evidenceHashes: [...value.evidenceHashes] as string[],
    confidence: value.confidence,
    confidenceRationale: value.confidenceRationale,
    status: value.status as ThreatMemoryStatus,
    createdBy: value.createdBy,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    expiresAt: value.expiresAt as string | null,
    validation,
  };
}


export function canRecallThreatMemory(memory: ThreatMemory, scope: MemoryRecallScope, now: string): boolean {
  if (!parseThreatMemory(memory) || memory.status !== "active" || !isIsoDate(now)) return false;
  if (memory.expiresAt !== null && Date.parse(memory.expiresAt) <= Date.parse(now)) return false;
  if (memory.scope.kind === "global") return scope.includeGlobal;
  if (memory.scope.workspaceId !== scope.workspaceId) return false;
  if (memory.scope.kind === "workspace") return true;
  return memory.scope.agentId === scope.agentId;
}
