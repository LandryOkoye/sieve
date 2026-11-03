import type { EvidencePointer, UntrustedText } from "@sieve/contracts";

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
  outcome: "signals_detected" | "no_signals_detected";
  findings: DetectionFinding[];
  quarantinedText: UntrustedText[];
};

type Rule = {
  category: ThreatCategory;
  signal: string;
  strength: DetectionFinding["strength"];
  rationale: string;
  pattern: RegExp;
};

const rules: Rule[] = [
  {
    category: "instruction_override",
    signal: "instruction_override_language",
    strength: "strong",
    rationale: "The text asks the reader to replace or ignore existing instructions.",
    pattern: /\b(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|system)?\s*(?:instructions?|rules?|prompts?)\b/i,
  },
  {
    category: "recommendation_steering",
    signal: "direct_recommendation_command",
    strength: "strong",
    rationale: "The text attempts to control what the agent recommends or conceals.",
    pattern: /\b(?:always|never|must|should)\b.{0,80}\b(?:recommend|promote|endorse|hide|avoid)\b/i,
  },
  {
    category: "memory_manipulation",
    signal: "memory_write_instruction",
    strength: "strong",
    rationale: "The text asks the reader to retain a claim, rule, or instruction.",
    pattern: /\b(?:remember|store|save|persist)\b.{0,80}\b(?:this|that|claim|rule|instruction|fact|asset|project)\b/i,
  },
  {
    category: "trust_manipulation",
    signal: "unsupported_trust_claim",
    strength: "moderate",
    rationale: "The text makes a trust or verification claim that requires independent evidence.",
    pattern: /\b(?:verified|safe|audited|official)\b/i,
  },
];

export function detect(textItems: readonly UntrustedText[]): DetectorVerdict {
  const findings: DetectionFinding[] = [];

  for (const item of textItems) {
    for (const rule of rules) {
      if (!rule.pattern.test(item.value)) continue;
      findings.push({
        category: rule.category,
        signal: rule.signal,
        strength: rule.strength,
        rationale: rule.rationale,
        evidence: item.evidence,
      });
    }
  }

  return {
    outcome: findings.length > 0 ? "signals_detected" : "no_signals_detected",
    findings,
    // Chain text remains explicitly untrusted even when no rule matches.
    quarantinedText: [...textItems],
  };
}
