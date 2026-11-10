import assert from "node:assert/strict";
import test from "node:test";
import { canRecallThreatMemory, parseThreatMemory, type ThreatMemory } from "@sieve/threat-memory/records";

const now = "2026-11-09T12:00:00.000Z";
const hash = "a".repeat(64);
const active: ThreatMemory = {
  id: "mem_1", schemaVersion: 1, scope: { kind: "workspace", workspaceId: "ws_1" },
  category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
  summary: "External content attempted to replace agent instructions.",
  behavioralFeatures: ["instruction hierarchy override"], safeFingerprint: hash,
  sourceType: "direct_content", evidenceHashes: [hash], confidence: 0.8,
  confidenceRationale: "A deterministic detector found an explicit override attempt.",
  status: "active", createdBy: "user_1", createdAt: now, updatedAt: now, expiresAt: null,
  validation: { reviewerId: "user_1", reviewedAt: now, rationale: "Reviewed defensive signal with corroborating evidence.", privacyReviewed: false, corroboratingWorkspaceIds: [] },
};

test("record parser rejects unrecognized fields and raw content", () => {
  assert.equal(parseThreatMemory({ ...active, rawContent: "private conversation" }), null);
  assert.deepEqual(parseThreatMemory(active), active);
});

test("recall requires active status, valid scope, and unexpired memory", () => {
  const allowed = { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: false };
  assert.equal(canRecallThreatMemory(active, allowed, now), true);
  assert.equal(canRecallThreatMemory(active, { ...allowed, workspaceId: "ws_2" }, now), false);
  assert.equal(canRecallThreatMemory({ ...active, expiresAt: "2026-11-08T00:00:00Z" }, allowed, now), false);
});
