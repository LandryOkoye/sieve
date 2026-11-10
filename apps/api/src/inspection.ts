import { detect } from "@sieve/detector";
import type { DetectionFinding, DetectorVerdict, UntrustedText } from "@sieve/contracts";
import { canRecallThreatMemory, parseThreatMemory, type MemoryRecallScope, type ThreatMemory } from "@sieve/threat-memory/lifecycle";

export type InspectionAction = "allow" | "review" | "block";
export type DirectInspectionResult = {
  verdict: DetectorVerdict;
  action: InspectionAction;
  memories: ThreatMemory[];
};
type SemanticReview = (text: readonly UntrustedText[], memories: readonly ThreatMemory[]) => Promise<{ findings: DetectionFinding[]; complete: boolean }>;

const genericRecallQuery = "agent defense instruction override trust manipulation recommendation steering memory manipulation";

function recallQuery(verdict: DetectorVerdict): string {
  const features = [...new Set(verdict.findings.flatMap(({ category, signal }) => [category, signal]))];
  return features.length ? features.join(" ") : genericRecallQuery;
}

function findingBelongsToContent(finding: DetectionFinding, text: readonly UntrustedText[]): boolean {
  const pointer = JSON.stringify(finding.evidence);
  return text.some((item) => JSON.stringify(item.evidence) === pointer);
}

function mergeFindings(current: readonly DetectionFinding[], contextual: readonly DetectionFinding[], text: readonly UntrustedText[]): DetectionFinding[] {
  const merged = [...current];
  for (const finding of contextual) {
    if (!findingBelongsToContent(finding, text)) continue;
    if (!merged.some((item) => item.category === finding.category && JSON.stringify(item.evidence) === JSON.stringify(finding.evidence))) {
      merged.push(finding);
    }
  }
  return merged;
}

export async function assessDirectContent(input: {
  textItems: readonly UntrustedText[];
  completeness: "complete" | "partial";
  scope: MemoryRecallScope;
  now: string;
  recall: (query: string) => Promise<readonly unknown[]>;
  semanticReview?: SemanticReview;
}): Promise<DirectInspectionResult> {
  const initial = detect(input.textItems, input.completeness);
  const recalled = await input.recall(recallQuery(initial));
  const memories = recalled.flatMap((item) => {
    const memory = parseThreatMemory(item);
    return memory && canRecallThreatMemory(memory, input.scope, input.now) ? [memory] : [];
  });

  let findings = initial.findings;
  let semanticComplete = !input.semanticReview;
  if (input.semanticReview) {
    const reviewed = await input.semanticReview(input.textItems, memories);
    findings = mergeFindings(findings, reviewed.findings, input.textItems);
    semanticComplete = reviewed.complete;
  }

  const outcome = findings.length > 0 ? "signals_detected" :
    input.completeness !== "complete" || !semanticComplete ? "uncertain" : "no_signals_detected";
  const verdict: DetectorVerdict = { ...initial, outcome, findings };
  const action: InspectionAction = findings.some((finding) => finding.strength === "strong") ? "block" :
    findings.length > 0 || outcome === "uncertain" ? "review" : "allow";
  return { verdict, action, memories };
}
