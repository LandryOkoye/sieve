import assert from "node:assert/strict";
import test from "node:test";
import { WalrusThreatMemory, namespaceForThreatScope } from "@sieve/threat-memory/walrus";
import type { ThreatMemory } from "@sieve/threat-memory/lifecycle";

const now = "2026-11-09T12:00:00.000Z";
const record: ThreatMemory = {
  id: "mem_1", schemaVersion: 1, scope: { kind: "agent", workspaceId: "ws_1", agentId: "agent_1" },
  category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
  summary: "External content attempted to replace agent instructions.",
  behavioralFeatures: ["instruction hierarchy override"], safeFingerprint: "a".repeat(64),
  sourceType: "direct_content", evidenceHashes: ["b".repeat(64)], confidence: 0.8,
  confidenceRationale: "A deterministic signal was recorded as a candidate for review.",
  status: "candidate", createdBy: "user_1", createdAt: now, updatedAt: now, expiresAt: null, validation: null,
};

function memoryClient() {
  const requests: Array<{ namespace: string; text?: string; query?: string }> = [];
  return {
    requests,
    rememberAndWait: async (text: string, namespace: string) => { requests.push({ namespace, text }); return { id: "job_1", blob_id: "blob_1" }; },
    listMemories: async ({ namespace }: { namespace: string }) => ({ has_more: false, next_cursor: null, memories: [{ blob_id: "blob_1", end_epoch: 99, expires_at: "2027-01-01T00:00:00Z" }] }),
    recall: async ({ namespace, query }: { namespace: string; query: string }) => { requests.push({ namespace, query }); return { results: [{ text: JSON.stringify(record), blob_id: "blob_1", distance: 0.2 }] }; },
    health: async () => undefined,
  };
}

test("Walrus lifecycle namespaces isolate scope and storage confirms blob expiry metadata", async () => {
  const agent = await namespaceForThreatScope("sieve-threat", record.scope);
  const workspace = await namespaceForThreatScope("sieve-threat", { kind: "workspace", workspaceId: "ws_1" });
  const custom = await namespaceForThreatScope("custom namespace ".repeat(14), record.scope);
  assert.notEqual(agent, workspace);
  assert.ok(custom.length < 200);
  assert.equal((await namespaceForThreatScope("sieve-threat", { kind: "global" })).endsWith("global"), true);
  const client = memoryClient();
  const walrus = new WalrusThreatMemory({ accountId: "acct", delegateKey: "key", serverUrl: "https://memory.test", namespace: "sieve-threat" }, client as never);
  const stored = await walrus.storeLifecycleRecord(record);
  assert.equal(stored.blobId, "blob_1");
  assert.deepEqual(stored.metadata, { endEpoch: 99, expiresAt: "2027-01-01T00:00:00Z" });
  assert.equal(client.requests[0]?.text?.includes("rawContent"), false);
});

test("recall queries only derived features and returns parsed memory hits by isolated namespace", async () => {
  const client = memoryClient();
  const walrus = new WalrusThreatMemory({ accountId: "acct", delegateKey: "key", serverUrl: "https://memory.test", namespace: "sieve-threat" }, client as never);
  const hits = await walrus.recallLifecycleRecords("instruction_override instruction_override_language", { workspaceId: "ws_1", agentId: "agent_1", includeGlobal: false });
  assert.equal(hits.length, 2);
  assert.equal(new Set(client.requests.map(({ namespace }) => namespace)).size, 2);
  assert.equal(hits.every((hit) => hit.memory.id === "mem_1"), true);
});

test("readiness probes signed recall access in addition to relayer health", async () => {
  const client = memoryClient();
  const walrus = new WalrusThreatMemory({ accountId: "acct", delegateKey: "key", serverUrl: "https://memory.test", namespace: "sieve-threat" }, client as never);
  await walrus.checkConnection();
  assert.equal(client.requests[0]?.namespace, "sieve-threat");
  assert.equal(client.requests[0]?.query, "sieve signed access probe");
});
