import assert from "node:assert/strict";
import test from "node:test";
import { reviewThreatMemory, type MemoryReviewer } from "@sieve/threat-memory/review";
import type { ThreatMemory } from "@sieve/threat-memory/records";

const now = "2026-11-09T12:00:00.000Z";
const hash = "a".repeat(64);
const candidate: ThreatMemory = {
  id: "mem_1", schemaVersion: 1, scope: { kind: "workspace", workspaceId: "ws_1" },
  category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
  summary: "External content attempted to replace agent instructions.",
  behavioralFeatures: ["instruction hierarchy override"], safeFingerprint: hash,
  sourceType: "direct_content", evidenceHashes: [hash], confidence: 0.8,
  confidenceRationale: "A deterministic detector found an explicit override attempt.",
  status: "candidate", createdBy: "user_1", createdAt: now, updatedAt: now,
  expiresAt: null, validation: null,
};
const reviewer: MemoryReviewer = { userId: "user_1", workspaceIds: ["ws_1"], canReviewGlobal: false };
const rationale = "Verified provenance and evidence spans against the inspection.";

test("workspace candidate requires authorized validation before promotion", () => {
  const validated = reviewThreatMemory(candidate, "validate", reviewer, { rationale }, now);
  assert.equal(validated.ok, true);
  if (!validated.ok) return;
  assert.equal(validated.memory.status, "validated");
  assert.equal(reviewThreatMemory(validated.memory, "promote", { ...reviewer, workspaceIds: ["ws_2"] }, { rationale }, now).ok, false);
  const promoted = reviewThreatMemory(validated.memory, "promote", reviewer, { rationale }, now);
  assert.equal(promoted.ok && promoted.memory.status, "active");
});

test("global promotion requires privacy review and two-workspace corroboration", () => {
  const global = { ...candidate, scope: { kind: "global" as const }, status: "validated" as const,
    validation: { reviewerId: "r", reviewedAt: now, rationale, privacyReviewed: false, corroboratingWorkspaceIds: [] } };
  assert.deepEqual(reviewThreatMemory(global, "promote", { userId: "r", workspaceIds: [], canReviewGlobal: true }, { rationale }, now), {
    ok: false, reason: "global_validation_requirements_missing",
  });
});

test("review requires a meaningful rationale and valid transition", () => {
  assert.deepEqual(reviewThreatMemory(candidate, "promote", reviewer, { rationale }, now), { ok: false, reason: "invalid_transition" });
  assert.deepEqual(reviewThreatMemory(candidate, "validate", reviewer, { rationale: "short" }, now), { ok: false, reason: "review_rationale_required" });
});
