import assert from "node:assert/strict";
import test from "node:test";
import { SieveClient } from "../../../packages/sdk/src/index.js";

function response(action: "allow" | "review" | "block"): Response {
  return new Response(JSON.stringify({ id: "inspection_1", contentHash: "a".repeat(64),
    assessment: { outcome: action === "allow" ? "no_signals_detected" : "signals_detected", findings: [] },
    decision: { action, policyVersion: 1 }, memoryEvidence: [], memoryLearning: [],
    createdAt: "2026-11-10T00:00:00.000Z", expiresAt: "2026-12-10T00:00:00.000Z" }), { status: 201 });
}

test("SDK puts content in trusted context only after an explicit allow", async () => {
  const queued: string[] = [];
  const quarantined: string[] = [];
  const client = new SieveClient({ baseUrl: "https://sieve.test", credential: `sieve_live_${"a".repeat(43)}`,
    fetch: async () => response("block") });
  const blocked = await client.inspectBeforeContext({ content: "malicious content", requestId: "req-1" }, {
    addTrusted: (text) => queued.push(text), quarantine: (text) => quarantined.push(text),
  });
  assert.equal(blocked.addedToTrustedContext, false);
  assert.deepEqual(queued, []);
  assert.deepEqual(quarantined, ["malicious content"]);
});

test("SDK passes the credential and correlation key and allows only an allow response", async () => {
  let requestHeaders: HeadersInit | undefined;
  let requestBody = "";
  const client = new SieveClient({ baseUrl: "https://sieve.test", credential: `sieve_live_${"a".repeat(43)}`,
    fetch: async (_url, init) => { requestHeaders = init?.headers; requestBody = String(init?.body); return response("allow"); } });
  const trusted: string[] = [];
  const result = await client.inspectBeforeContext({ content: "benign text", sourceType: "document", requestId: "request-2" }, {
    addTrusted: (text) => trusted.push(text),
  });
  const headers = new Headers(requestHeaders);
  assert.equal(headers.get("idempotency-key"), "request-2");
  assert.match(headers.get("authorization") ?? "", /^Bearer sieve_live_/);
  assert.deepEqual(JSON.parse(requestBody), { content: "benign text", sourceType: "document" });
  assert.equal(result.addedToTrustedContext, true);
  assert.deepEqual(trusted, ["benign text"]);
});
