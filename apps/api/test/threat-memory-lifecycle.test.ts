import assert from "node:assert/strict";
import test from "node:test";
import {
  canRecallThreatMemory,
  parseThreatMemory,
  reviewThreatMemory,
  type MemoryReviewer,
  type ThreatMemory,
} from "@sieve/threat-memory/lifecycle";

const now = "2026-11-09T12:00:00.000Z";
const hash = "a".repeat(64);

function memory(overrides: Partial<ThreatMemory> = {}): ThreatMemory {
  return {
    id: "mem_1",
    schemaVersion: 1,
    scope: { kind: "workspace", workspaceId: "ws_1" },
    category: "instruction_override",
    techniqueId: "instruction-hierarchy-manipulation",
    summary: "External content attempted to replace agent instructions.",
    behavioralFeatures: ["instruction hierarchy override"],
    safeFingerprint: hash,
    sourceType: "direct_content",
    evidenceHashes: [hash],
    confidence: 0.8,
    confidenceRationale: "A deterministic detector found an explicit override attempt.",
    status: "candidate",
    createdBy: "user_1",
    createdAt: now,
    updatedAt: now,
    expiresAt: null,
    validation: null,
    ...overrides,
  };
}

const workspaceReviewer: MemoryReviewer = {
  userId: "user_1",
  workspaceIds: ["ws_1"],
  canReviewGlobal: false,
};

test("candidate memory is not eligible for recall", () => {
  assert.equal(canRecallThreatMemory(memory(), { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: true }, now), false);
});

test("authorized validation keeps a candidate out of recall until separately promoted", () => {
  const result = reviewThreatMemory(memory(), "validate", workspaceReviewer, {
    rationale: "Verified provenance and evidence spans against the inspection.",
  }, now);

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.memory.status, "validated");
  assert.equal(canRecallThreatMemory(result.memory, { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: false }, now), false);
});

test("only an authorized workspace reviewer can promote validated memory", () => {
  const validated = reviewThreatMemory(memory(), "validate", workspaceReviewer, {
    rationale: "Verified provenance and evidence spans against the inspection.",
  }, now);
  assert.equal(validated.ok, true);
  if (!validated.ok) return;

  const rejected = reviewThreatMemory(validated.memory, "promote", {
    userId: "user_2",
    workspaceIds: ["ws_2"],
    canReviewGlobal: false,
  }, { rationale: "Trying to promote another workspace's memory." }, now);
  assert.deepEqual(rejected, { ok: false, reason: "not_authorized" });

  const promoted = reviewThreatMemory(validated.memory, "promote", workspaceReviewer, {
    rationale: "Approved for workspace defensive recall.",
  }, now);
  assert.equal(promoted.ok, true);
  if (promoted.ok) assert.equal(promoted.memory.status, "active");
});

test("workspace memory cannot be recalled from another workspace", () => {
  const active = memory({ status: "active" });
  assert.equal(canRecallThreatMemory(active, { workspaceId: "ws_2", agentId: "agent_2", includeGlobal: true }, now), false);
});

test("agent memory is visible only to that agent in its workspace", () => {
  const active = memory({
    scope: { kind: "agent", workspaceId: "ws_1", agentId: "agent_1" },
    status: "active",
    validation: {
      reviewerId: "user_1",
      reviewedAt: now,
      rationale: "Reviewed and approved for this agent.",
      privacyReviewed: false,
      corroboratingWorkspaceIds: [],
    },
  });
  assert.equal(canRecallThreatMemory(active, { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: false }, now), true);
  assert.equal(canRecallThreatMemory(active, { workspaceId: "ws_1", agentId: "agent_2", includeGlobal: true }, now), false);
  assert.equal(canRecallThreatMemory(active, { workspaceId: "ws_2", agentId: "agent_1", includeGlobal: true }, now), false);
});

test("global memory is opt-in and requires privacy review plus two-workspace corroboration", () => {
  const global = memory({
    scope: { kind: "global" },
    status: "validated",
    validation: {
      reviewerId: "reviewer",
      reviewedAt: now,
      rationale: "Reviewed but missing the global promotion requirements.",
      privacyReviewed: false,
      corroboratingWorkspaceIds: [],
    },
  });
  const reviewer: MemoryReviewer = { userId: "reviewer", workspaceIds: [], canReviewGlobal: true };
  const invalid = reviewThreatMemory(global, "promote", reviewer, {
    rationale: "This is globally useful.",
  }, now);
  assert.deepEqual(invalid, { ok: false, reason: "global_validation_requirements_missing" });

  const eligible = memory({
    scope: { kind: "global" },
    status: "validated",
    validation: {
      reviewerId: "reviewer",
      reviewedAt: now,
      rationale: "Corroborated across independent workspaces.",
      privacyReviewed: true,
      corroboratingWorkspaceIds: ["ws_1", "ws_2"],
    },
  });
  const promoted = reviewThreatMemory(eligible, "promote", reviewer, {
    rationale: "Approved for global defensive recall.",
  }, now);
  assert.equal(promoted.ok, true);
  if (!promoted.ok) return;
  assert.equal(canRecallThreatMemory(promoted.memory, { workspaceId: "ws_3", agentId: "agent_3", includeGlobal: false }, now), false);
  assert.equal(canRecallThreatMemory(promoted.memory, { workspaceId: "ws_3", agentId: "agent_3", includeGlobal: true }, now), true);
});

test("expired, rejected, and malformed memories cannot be recalled", () => {
  assert.equal(canRecallThreatMemory(memory({ status: "active", expiresAt: "2026-11-08T00:00:00.000Z" }), { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: true }, now), false);
  assert.equal(canRecallThreatMemory(memory({ status: "rejected" }), { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: true }, now), false);
  assert.equal(parseThreatMemory({ ...memory({ status: "active" }), rawContent: "private conversation" }), null);
});

test("a reviewer must provide a rationale and valid state transition", () => {
  assert.deepEqual(reviewThreatMemory(memory(), "promote", workspaceReviewer, { rationale: "Direct promotion." }, now), {
    ok: false,
    reason: "invalid_transition",
  });
  assert.deepEqual(reviewThreatMemory(memory(), "validate", workspaceReviewer, { rationale: "short" }, now), {
    ok: false,
    reason: "review_rationale_required",
  });
});

test("revoked validated memory remains structurally valid but is not recallable", () => {
  const validated = reviewThreatMemory(memory(), "validate", workspaceReviewer, {
    rationale: "Reviewed evidence and provenance for defensive use.",
  }, now);
  assert.equal(validated.ok, true);
  if (!validated.ok) return;
  const revoked = reviewThreatMemory(validated.memory, "revoke", workspaceReviewer, {
    rationale: "Revoked after new information invalidated prior assumptions.",
  }, now);
  assert.equal(revoked.ok, true);
  if (!revoked.ok) return;
  assert.equal(parseThreatMemory(revoked.memory)?.status, "revoked");
  assert.equal(canRecallThreatMemory(revoked.memory, { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: false }, now), false);
});
