import assert from "node:assert/strict";
import test from "node:test";
import { judgeUntrustedText } from "@sieve/detector";

const config = { provider: "openai-responses" as const, apiKey: "unit-test-key", model: "test-model", baseUrl: "https://judge.test/v1" };
test("semantic review receives memory in a separate untrusted field and returns evidence only for current content", async () => {
  const originalFetch = globalThis.fetch;
  let submitted: Record<string, unknown> | undefined;
  globalThis.fetch = async (_url, init) => {
    submitted = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify({ output_text: JSON.stringify({ items: [{ index: 0, verdict: "attack", categories: ["instruction_override"], rationale: "Current text attempts to supersede instructions." }] }) }), { status: 200 });
  };
  try {
    const evidence = { contentSha256: "a".repeat(64) };
    const result = await judgeUntrustedText([{ field: "webpage", value: "A novel paraphrase of an instruction attack.", evidence }], config, [{
      category: "instruction_override", techniqueId: "instruction-hierarchy-manipulation",
      summary: "A validated pattern describes attempts to replace agent instructions.",
      behavioralFeatures: ["instruction hierarchy override"],
    }]);
    const input = submitted?.input as Array<{ role: string; content: Array<{ text: string }> }>;
    const payload = JSON.parse(input[1]?.content[0]?.text ?? "{}") as { inspectedContent: unknown[]; recalledThreatMemory: unknown[] };
    assert.equal(payload.inspectedContent.length, 1);
    assert.equal(payload.recalledThreatMemory.length, 1);
    assert.equal("tools" in (submitted ?? {}), false);
    assert.equal(submitted?.store, false);
    assert.deepEqual(result.findings[0]?.evidence, evidence);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
