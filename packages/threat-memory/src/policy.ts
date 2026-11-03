import type { EvidenceBundle, EvidencePointer, LookupTarget } from "@sieve/contracts";
import type { DetectionFinding, ThreatCategory } from "@sieve/detector";

export type ThreatMemoryRecord = {
  schemaVersion: 1;
  category: ThreatCategory;
  pattern: string;
  summary: string;
  source: {
    network: EvidenceBundle["network"];
    target: LookupTarget;
    providerMethod: string;
    retrievedAt: string;
    field: string;
    evidence: EvidencePointer;
  };
};

export type MemoryWriteDecision =
  | { allowed: true; record: ThreatMemoryRecord }
  | { allowed: false; reason: string };

const summaries: Record<ThreatCategory, string> = {
  instruction_override: "Chain text attempted to replace or ignore an agent's existing instructions.",
  trust_manipulation: "Chain text asserted trust or verification without independent supporting evidence.",
  recommendation_steering: "Chain text attempted to control an agent's recommendations or concealment.",
  memory_manipulation: "Chain text attempted to make an agent retain a claim, rule, or instruction.",
};

const acceptedSignals: Record<ThreatCategory, ReadonlySet<string>> = {
  instruction_override: new Set(["instruction_override_language"]),
  trust_manipulation: new Set(["unsupported_trust_claim"]),
  recommendation_steering: new Set(["direct_recommendation_command"]),
  memory_manipulation: new Set(["memory_write_instruction"]),
};

function samePointer(left: EvidencePointer, right: EvidencePointer): boolean {
  return (
    left.digest === right.digest &&
    left.objectId === right.objectId &&
    left.eventIndex === right.eventIndex
  );
}

function matchesTarget(pointer: EvidencePointer, target: LookupTarget): boolean {
  if (target.kind === "transaction") return pointer.digest === target.digest;
  return pointer.objectId === target.objectId;
}

export function authorizeMemoryWrite(
  finding: DetectionFinding,
  evidence: EvidenceBundle,
): MemoryWriteDecision {
  if (evidence.provider !== "tatum-sui-grpc" || evidence.completeness !== "complete") {
    return { allowed: false, reason: "complete_tatum_evidence_required" };
  }

  if (finding.strength !== "strong") {
    return { allowed: false, reason: "strong_detector_signal_required" };
  }

  if (!acceptedSignals[finding.category]?.has(finding.signal)) {
    return { allowed: false, reason: "unrecognized_detector_signal" };
  }

  const sourceText = evidence.untrustedText.find((item) => samePointer(item.evidence, finding.evidence));
  if (!sourceText || !matchesTarget(finding.evidence, evidence.target)) {
    return { allowed: false, reason: "finding_provenance_does_not_match_case" };
  }

  return {
    allowed: true,
    record: {
      schemaVersion: 1,
      category: finding.category,
      pattern: finding.signal,
      summary: summaries[finding.category],
      source: {
        network: evidence.network,
        target: evidence.target,
        providerMethod: evidence.providerMethod,
        retrievedAt: evidence.retrievedAt,
        field: sourceText.field.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 80),
        evidence: finding.evidence,
      },
    },
  };
}
