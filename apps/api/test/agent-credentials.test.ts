import assert from "node:assert/strict";
import test from "node:test";
import { hashAgentCredential, issueAgentCredential, readAgentBearer } from "../src/agent-credentials.js";

test("issued agent credentials have high entropy and persist only a SHA-256 verifier", () => {
  const issued = issueAgentCredential();
  assert.match(issued.secret, /^sieve_live_[A-Za-z0-9_-]{43}$/);
  assert.match(issued.tokenHash, /^[a-f0-9]{64}$/);
  assert.equal(issued.tokenHash, hashAgentCredential(issued.secret));
  assert.notEqual(issued.tokenHash, issued.secret);
  assert.equal(issued.prefix, issued.secret.slice(0, 20));
});

test("credential parser rejects malformed and truncated bearer secrets", () => {
  assert.equal(hashAgentCredential(""), null);
  assert.equal(hashAgentCredential("sieve_live_short"), null);
  assert.equal(hashAgentCredential("sieve_live_" + "a".repeat(43) + "!"), null);
});

test("bearer parser accepts exactly one complete SIEVE agent key", () => {
  const secret = issueAgentCredential().secret;
  assert.equal(readAgentBearer(`Bearer ${secret}`), secret);
  assert.equal(readAgentBearer(`bearer ${secret}`), null);
  assert.equal(readAgentBearer(`Bearer ${secret} extra`), null);
});
