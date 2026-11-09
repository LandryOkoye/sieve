import assert from "node:assert/strict";
import test from "node:test";
import { Database } from "../src/database.js";
import { issueAgentCredential } from "../src/agent-credentials.js";

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
