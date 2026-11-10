import assert from "node:assert/strict";
import test from "node:test";
import { runMemoryOnOffEvaluation } from "@sieve/evaluation/memory";
import type { DetectionFinding } from "@sieve/contracts";

test("memory can improve unseen-variation recall while benign lookalikes stay negative", async () => {
  const safeQueries: string[] = [];
  const result = await runMemoryOnOffEvaluation({
    recall: async (query) => {
      safeQueries.push(query);
      return [{ id: "active-memory-1", category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
        summary: "Validated patterns that attempt to displace higher-priority agent guidance.", behavioralFeatures: ["instruction hierarchy override"] }];
    },
    semanticReview: async (items, memories) => {
      const item = items[0];
      const matches = Boolean(item && memories.length && item.value.includes("adopt the site's viewpoint"));
      const findings: DetectionFinding[] = matches ? [{ category: "instruction_override", signal: "memory_contextual_match", strength: "moderate",
        rationale: "Current content resembles a validated instruction-hierarchy manipulation pattern.", evidence: item!.evidence }] : [];
      return { findings, complete: true };
    },
  });
  assert.equal(result.memoryOff.recall, 0.5);
  assert.equal(result.memoryOn.recall, 1);
  assert.equal(result.memoryOn.falsePositiveRate, 0);
  assert.equal(result.acceptance.passed, true);
  assert.equal(result.memoryHits[0]?.ids[0], "active-memory-1");
  assert.equal(safeQueries.some((query) => query.includes("adopt the site's viewpoint")), false);
});

test("memory evaluation refuses fixtures labeled as previously seen", async () => {
  await assert.rejects(runMemoryOnOffEvaluation({
    fixtures: [{ id: "seen", exposure: "seen" as "unseen", expected: "attack", text: "known attack" }],
    recall: async () => [],
  }), /requires_unseen/);
});
