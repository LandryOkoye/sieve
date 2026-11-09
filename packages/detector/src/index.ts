import type { DetectionFinding, DetectorVerdict, ThreatCategory, UntrustedText } from "@sieve/contracts";
export type { DetectionFinding, DetectorVerdict, ThreatCategory } from "@sieve/contracts";
export { judgeUntrustedText, type SemanticJudgeConfig, type SemanticJudgeResult } from "./judge.js";

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
    pattern: /\b(?:(?:ignore|disregard|override|forget|replace|abandon|cancel|supplant|suspend|withdraw|discard|set aside|put aside)\b.{0,60}\b(?:instructions?|rules?|prompts?|directions?|guidance|policies|directives?|constraints?)|(?:instructions?|rules?|prompts?|directions?|guidance|policies|directives?|constraints?)\b.{0,35}\b(?:aside|set aside)|(?:previous|prior|above|existing|earlier|old|former)\s+(?:instructions?|rules?|prompts?|directions?|guidance|policies|directives?|constraints?)\b.{0,40}\b(?:no longer apply|do not apply|don't apply|are void|are obsolete|are no longer binding)|(?:instructions?|rules?|prompts?|directions?|guidance|policies|directives?|constraints?)\s+(?:above|prior|previous|old)\b.{0,40}\b(?:no longer apply|do not apply|don't apply|are void|are obsolete)|(?:this|the new|following)\s+(?:message|prompt|text|policy)\b.{0,40}\b(?:replace|replaces|override|supersedes?)\b|(?:policy|directive|instruction|message)\b.{0,40}\b(?:replace|replaces|override|supersedes?)\b.{0,40}\b(?:directions?|instructions?|rules?|prompt|guidance)\b|(?:this|the following|new)\s+(?:message|prompt|text|content|description|metadata)\b.{0,45}\b(?:instructions?|rules?|policies|directives?|governing prompt)|(?:from now on|starting now)\b.{0,40}\b(?:obey|follow|use|treat)\b.{0,40}\b(?:this|the following|this page|this description)\b|nothing\s+(?:above|earlier|prior)\b.{0,30}\b(?:applies|counts|is binding)\b)/i,
  },
  {
    category: "recommendation_steering",
    signal: "direct_recommendation_command",
    strength: "strong",
    rationale: "The text attempts to control what the agent recommends or conceals.",
    pattern: /\b(?:always|never|must|should|do not|don't|avoid|make|rank|put|present|tell|feature|describe|call|steer|frame|keep|recommend)\b.{0,80}\b(?:recommend|recommendation|promote|endorse|hide|omit|avoid|mention|disclose|feature|present|describe|buy|choose|superior|safest|leading choice|top pick|first choice|best choice|best recommendation|number one|above all|alternatives?|rival tokens?|competing|downside|problems?|risks?|unfavorable|first|top)\b/i,
  },
  {
    category: "memory_manipulation",
    signal: "memory_write_instruction",
    strength: "strong",
    rationale: "The text asks the reader to retain a claim, rule, or instruction.",
    pattern: /\b(?:remember|store|save|persist|retain|preserve|keep|add|write|carry|include|make|ensure|update|tell)\b.{0,80}\b(?:this|that|our|claim|rule|instruction|fact|asset|project|token|approval|memory|context|note|status|for future|future (?:sessions|agents|assistants)|standing)\b/i,
  },
  {
    category: "trust_manipulation",
    signal: "unsupported_trust_claim",
    strength: "moderate",
    rationale: "The text asserts project safety, verification, or audit status that requires independent evidence.",
    pattern: /\b(?:(?:project|token|coin|collection|protocol|asset|smart contract|contracts?)\b.{0,65}\b(?:officially\s+)?(?:verified|safe|audited|certified|endorsed|official|approved|authorized|validated|legitimate|trustworthy|guaranteed|risk[- ]free)\b(?!\s+to\s+(?:browse|use|view|visit|explore))(?!\s+(?:(?:(?:social|community|support|news|event)\s+)?(?:account|profile|page|channel|directory|site|website|schedule|calendar|announcement|feed|post|event|link)))|(?:project|token|coin|collection|protocol|asset|contract)\b.{0,55}\b(?:is|are|has been|have been)?\s*(?:formally\s+)?(?:recognized|backed|supported)\b.{0,30}\b(?:official|approved|certified|auditor|foundation|safe|legitimate)|official\s+(?:collection|project|token|coin|protocol|asset|contract|source)\b(?!\s+(?:(?:social|community|support|news|event)\s+)?(?:account|profile|page|channel|directory|site|website|schedule|calendar|announcement|feed|post|event|link))|(?:smart\s+)?contracts?\b.{0,35}\b(?:passed|cleared|completed|received|underwent)\b.{0,20}\baudit\b)/i,
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
