import assert from "node:assert/strict";
import test from "node:test";
import { Database } from "../src/database.js";
import { issueAgentCredential } from "../src/agent-credentials.js";
import { reviewThreatMemory, type MemoryReviewer } from "@sieve/threat-memory/lifecycle";

const url = process.env.TEST_DATABASE_URL;
test("PostgreSQL agent credentials and direct inspections are scoped and idempotent", { skip: !url }, async () => {
  const db = new Database(url!);
  try {
    await db.migrate();
    const userId = await db.resolveUserId("https://test.invalid", `sub-${crypto.randomUUID()}`);
    const key = issueAgentCredential();
    const agent = await db.createProtectedAgent(userId, "integration agent", { id: crypto.randomUUID(), tokenHash: key.tokenHash, prefix: key.prefix });
    assert.equal((await db.authenticateAgent(key.tokenHash, "inspect"))?.id, agent.id);
    assert.equal(await db.authenticateAgent("f".repeat(64), "inspect"), null);
    const input = { agentId: agent.id, workspaceId: agent.workspaceId, requestId: "request-1", contentHash: "a".repeat(64), contentBytes: 20,
      sourceType: "direct_content", sourceRefHash: null, outcome: "no_signals_detected" as const, action: "allow" as const,
      findings: [], memoryIds: [], detectorVersion: "rules-v1", policyVersion: agent.policyVersion };
    const first = await db.saveDirectInspection(input);
    const retry = await db.saveDirectInspection(input);
    assert.equal("conflict" in first, false);
    assert.equal("conflict" in retry, false);
    if ("conflict" in first || "conflict" in retry) return;
    assert.equal(first.created, true);
    assert.equal(retry.created, false);
    assert.equal(first.inspection.id, retry.inspection.id);
    assert.deepEqual(retry.inspection.memoryIds, []);
    assert.equal("content" in retry.inspection, false);
  } finally {
    await db.close();
  }
});

test("PostgreSQL memory lifecycle is reviewer-authorized and recall requires the active blob reference", { skip: !url }, async () => {
  const db = new Database(url!);
  try {
    await db.migrate();
    const userId = await db.resolveUserId("https://review.invalid", `owner-${crypto.randomUUID()}`);
    const agent = await db.createProtectedAgent(userId, "memory lifecycle agent", { id: crypto.randomUUID(), tokenHash: "c".repeat(64), prefix: "sieve_live_test" });
    const sourceInspection = await db.saveDirectInspection({ agentId: agent.id, workspaceId: agent.workspaceId, requestId: "memory-source",
      contentHash: "e".repeat(64), contentBytes: 32, sourceType: "direct_content", sourceRefHash: null,
      outcome: "signals_detected", action: "block", findings: [], memoryIds: [], detectorVersion: "rules-v1", policyVersion: 1 });
    assert.equal("conflict" in sourceInspection, false);
    if ("conflict" in sourceInspection) return;
    const now = "2026-11-09T12:00:00.000Z";
    const hash = "d".repeat(64);
    const candidateResult = await db.createThreatMemoryCandidate({
      id: crypto.randomUUID(), schemaVersion: 1, scope: { kind: "agent", workspaceId: agent.workspaceId, agentId: agent.id },
      category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
      summary: "External content attempted to replace agent instructions.", behavioralFeatures: ["instruction hierarchy override"],
      safeFingerprint: hash, sourceType: "direct_content", evidenceHashes: [hash], confidence: 0.8,
      confidenceRationale: "A deterministic rule identified an instruction override attempt.", status: "candidate",
      createdBy: userId, createdAt: now, updatedAt: now, expiresAt: "2027-02-07T12:00:00.000Z", validation: null,
    }, sourceInspection.inspection.id);
    const candidate = candidateResult.memory;
    const repeatedCandidate = await db.createThreatMemoryCandidate({ ...candidate, id: crypto.randomUUID() }, sourceInspection.inspection.id);
    assert.equal(repeatedCandidate.memory.id, candidate.id);
    await db.completeLifecycleMemoryWrite(candidate.id, "candidate-job", "candidate-blob", 80, "2027-01-01T00:00:00.000Z");
    const unauthorized = await db.resolveUserId("https://review.invalid", `other-${crypto.randomUUID()}`);
    assert.equal(await db.getThreatMemoryForReview(unauthorized, candidate.id, false), null);
    const reviewer: MemoryReviewer = { userId, workspaceIds: [agent.workspaceId], canReviewGlobal: false };
    const validated = reviewThreatMemory(candidate, "validate", reviewer, { rationale: "Verified provenance against the persisted inspection." }, now);
    assert.equal(validated.ok, true);
    if (!validated.ok) return;
    assert.equal(await db.saveThreatMemoryReview({ memory: validated.memory, action: "validate", reviewerId: userId, canReviewGlobal: false,
      rationale: "Verified provenance against the persisted inspection.", details: {}, expectedStatus: "candidate" }), true);
    const reloaded = await db.getThreatMemoryForReview(userId, candidate.id, false);
    assert.equal(reloaded?.memory.status, "validated");
    const promoted = reviewThreatMemory(reloaded!.memory, "promote", reviewer, { rationale: "Promoted for this agent's defensive recall." }, now);
    assert.equal(promoted.ok, true);
    if (!promoted.ok) return;
    assert.equal(await db.saveThreatMemoryReview({ memory: promoted.memory, action: "promote", reviewerId: userId, canReviewGlobal: false,
      rationale: "Promoted for this agent's defensive recall.", details: {}, expectedStatus: "validated", blobId: "active-blob",
      endEpoch: 100, expiresAt: "2027-01-01T00:00:00.000Z" }), true);
    const scope = { workspaceId: agent.workspaceId, agentId: agent.id, includeGlobal: false };
    const recalled = await db.authorizeRecalledMemories(agent, scope, [
      { memory: promoted.memory, blobId: "candidate-blob" }, { memory: promoted.memory, blobId: "active-blob" },
    ], now);
    assert.deepEqual(recalled.map(({ id }) => id), [candidate.id]);
  } finally {
    await db.close();
  }
});
