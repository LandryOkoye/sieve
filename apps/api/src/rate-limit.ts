type WindowEntry = { count: number; resetAt: number };

export class FixedWindowRateLimiter {
  private readonly windows = new Map<string, WindowEntry>();
  constructor(private readonly limit: number, private readonly windowMs: number, private readonly maximumKeys = 20_000) {
    if (!Number.isInteger(limit) || limit < 1 || windowMs < 1 || maximumKeys < 1) throw new Error("invalid_rate_limit_configuration");
  }

  consume(key: string, now = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    let entry = this.windows.get(key);
    if (!entry || entry.resetAt <= now) {
      if (this.windows.size >= this.maximumKeys) {
        for (const [candidate, value] of this.windows) {
          if (value.resetAt <= now) this.windows.delete(candidate);
        }
        if (this.windows.size >= this.maximumKeys) this.windows.delete(this.windows.keys().next().value!);
      }
      entry = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, entry);
    }
    if (entry.count >= this.limit) return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) };
    entry.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }
}
