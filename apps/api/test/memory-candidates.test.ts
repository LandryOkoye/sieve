import assert from "node:assert/strict";
import test from "node:test";
import { createThreatMemoryCandidate } from "../src/memory-candidates.js";
import type { DetectionFinding } from "@sieve/contracts";

const finding: DetectionFinding = { category: "instruction_override", signal: "instruction_override_language", strength: "strong",
  rationale: "The text asks the reader to replace or ignore existing instructions.", evidence: { contentSha256: "b".repeat(64) } };

test("candidate contains minimized SIEVE-authored features and requires review", () => {
  const memory = createThreatMemoryCandidate({ finding, scope: { kind: "agent", workspaceId: "ws_1", agentId: "agent_1" },
    contentHash: "b".repeat(64), sourceType: "direct_content", now: "2026-11-09T12:00:00.000Z", id: "mem_1" });
  assert.equal(memory.status, "candidate");
  assert.equal(memory.validation, null);
  assert.deepEqual(memory.behavioralFeatures, ["instruction_override_language", "instruction_override"]);
  assert.equal(memory.evidenceHashes[0], "b".repeat(64));
  assert.equal(JSON.stringify(memory).includes("replace or ignore existing instructions"), false);
  assert.equal(Date.parse(memory.expiresAt!) - Date.parse(memory.createdAt), 90 * 24 * 60 * 60 * 1_000);
});
