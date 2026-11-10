import assert from "node:assert/strict";
import test from "node:test";
import { FixedWindowRateLimiter } from "../src/rate-limit.js";

test("agent rate limit is scoped by key and resets at the window boundary", () => {
  const limiter = new FixedWindowRateLimiter(2, 10_000);
  assert.equal(limiter.consume("agent-a", 100).allowed, true);
  assert.equal(limiter.consume("agent-a", 200).allowed, true);
  assert.deepEqual(limiter.consume("agent-a", 300), { allowed: false, retryAfterSeconds: 10 });
  assert.equal(limiter.consume("agent-b", 300).allowed, true);
  assert.equal(limiter.consume("agent-a", 10_100).allowed, true);
});

test("rate limiter rejects invalid limits", () => {
  assert.throws(() => new FixedWindowRateLimiter(0, 1000), /invalid_rate_limit/);
});
