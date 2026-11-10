import { createHash, randomBytes } from "node:crypto";

const credentialPattern = /^sieve_live_[A-Za-z0-9_-]{43}$/;

export function issueAgentCredential(): { secret: string; tokenHash: string; prefix: string } {
  const secret = `sieve_live_${randomBytes(32).toString("base64url")}`;
  return { secret, tokenHash: createHash("sha256").update(secret).digest("hex"), prefix: secret.slice(0, 20) };
}

export function hashAgentCredential(secret: string): string | null {
  if (!credentialPattern.test(secret)) return null;
  return createHash("sha256").update(secret).digest("hex");
}

export function readAgentBearer(authorization: string | undefined): string | null {
  if (!authorization || authorization.length > 128) return null;
  const match = authorization.match(/^Bearer (sieve_live_[A-Za-z0-9_-]{43})$/);
  return match?.[1] ?? null;
}
