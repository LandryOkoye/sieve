import type { DetectionFinding, DetectorVerdict, ThreatCategory, UntrustedText } from "@sieve/contracts";
export type { DetectionFinding, DetectorVerdict, ThreatCategory } from "@sieve/contracts";

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
    pattern: /\b(?:(?:ignore|disregard|override|forget|replace|abandon|set aside|put aside)\b.{0,60}\b(?:instructions?|rules?|prompts?|directions?|guidance)|(?:instructions?|rules?|prompts?|directions?|guidance)\b.{0,35}\b(?:aside|set aside)|(?:previous|prior|above|existing|earlier|old)\s+(?:instructions?|rules?|prompts?|directions?)\b.{0,40}\b(?:no longer apply|do not apply|don't apply|are void|are obsolete)|(?:instructions?|rules?|prompts?|directions?)\s+(?:above|prior|previous|old)\b.{0,40}\b(?:no longer apply|do not apply|don't apply|are void|are obsolete)|(?:this|the new|following)\s+(?:message|prompt|text)\b.{0,40}\b(?:replace|override|supersedes?)\b)/i,
  },
  {
    category: "recommendation_steering",
    signal: "direct_recommendation_command",
    strength: "strong",
    rationale: "The text attempts to control what the agent recommends or conceals.",
    pattern: /\b(?:always|never|must|should|do not|don't|avoid|make|rank|put|present|tell)\b.{0,80}\b(?:recommend|recommendation|promote|endorse|hide|avoid|mention|disclose|top pick|first choice|best choice|best recommendation|number one|above all|competing|downside|problems?|risks?)\b/i,
  },
  {
    category: "memory_manipulation",
    signal: "memory_write_instruction",
    strength: "strong",
    rationale: "The text asks the reader to retain a claim, rule, or instruction.",
    pattern: /\b(?:remember|store|save|persist|retain|preserve|keep|add|write)\b.{0,80}\b(?:this|that|claim|rule|instruction|fact|asset|project|memory|context|for future)\b/i,
  },
  {
    category: "trust_manipulation",
    signal: "unsupported_trust_claim",
    strength: "moderate",
    rationale: "The text asserts project safety, verification, or audit status that requires independent evidence.",
    pattern: /\b(?:(?:project|token|coin|collection|protocol|asset|smart contract|contracts?)\b.{0,55}\b(?:officially\s+)?(?:verified|safe|audited|certified|endorsed|official|approved)\b(?!\s+to\s+(?:browse|use|view|visit|explore))(?!\s+account\b)|official\s+(?:collection|project|token|coin|protocol|asset|contract)|(?:project|token|coin|collection|protocol|asset|smart\s+contract|contracts?)\b.{0,35}\b(?:passed|cleared|completed|received|underwent)\b.{0,20}\baudit\b)/i,
  },
];

export function detect(
  textItems: readonly UntrustedText[],
  evidenceCompleteness: "complete" | "partial" = "complete",
): DetectorVerdict {
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
    outcome: findings.length > 0
      ? "signals_detected"
      : evidenceCompleteness === "complete"
        ? "no_signals_detected"
        : "uncertain",
    findings,
    // Chain text remains explicitly untrusted even when no rule matches.
    quarantinedText: [...textItems],
  };
}
