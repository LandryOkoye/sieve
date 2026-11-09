import { createHash, randomUUID } from "node:crypto";
import type { DetectionFinding } from "@sieve/contracts";
import type { ThreatMemory, ThreatMemoryScope } from "@sieve/threat-memory/lifecycle";

const summaries: Record<DetectionFinding["category"], string> = {
  instruction_override: "External content attempted to replace or bypass an agent instruction hierarchy.",
  trust_manipulation: "External content asserted unsupported safety, verification, or authorization claims.",
  recommendation_steering: "External content attempted to steer recommendations or conceal material risks.",
  memory_manipulation: "External content attempted to persist a claim or instruction into future context.",
};

const techniques: Record<DetectionFinding["category"], string> = {
  instruction_override: "instruction-hierarchy-manipulation",
  trust_manipulation: "unsupported-trust-assertion",
  recommendation_steering: "recommendation-steering",
  memory_manipulation: "persistent-context-manipulation",
};

export function createThreatMemoryCandidate(input: {
  finding: DetectionFinding;
  scope: ThreatMemoryScope;
  contentHash: string;
  sourceType: string;
  now: string;
  id?: string;
}): ThreatMemory {
  if (!/^[a-f0-9]{64}$/i.test(input.contentHash) || !Number.isFinite(Date.parse(input.now))) {
    throw new Error("invalid_memory_candidate_evidence");
  }
  const safeFingerprint = createHash("sha256").update(`sieve-threat-v1:${input.finding.category}:${input.finding.signal}`).digest("hex");
  return {
    id: input.id ?? randomUUID(),
    schemaVersion: 1,
    scope: input.scope,
    category: input.finding.category,
    techniqueId: techniques[input.finding.category],
    summary: summaries[input.finding.category],
    behavioralFeatures: [input.finding.signal, input.finding.category],
    safeFingerprint,
    sourceType: input.sourceType,
    evidenceHashes: [input.contentHash],
    confidence: input.finding.strength === "strong" ? 0.82 : 0.56,
    confidenceRationale: `SIEVE detector signal ${input.finding.signal} created this candidate; authorized review is required before recall.`,
    status: "candidate",
    createdBy: "sieve-runtime",
    createdAt: input.now,
    updatedAt: input.now,
    expiresAt: new Date(Date.parse(input.now) + 90 * 24 * 60 * 60 * 1_000).toISOString(),
    validation: null,
  };
}
