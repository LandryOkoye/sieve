import { createRemoteJWKSet, jwtVerify } from "jose";

export type OidcConfig = {
  issuer: string;
  audience: string;
  jwksUrl: string;
};

export type AuthenticatedPrincipal = {
  issuer: string;
  subject: string;
};

export class OidcAuthenticator {
  private readonly config: OidcConfig;
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;
  private checkedAt = 0;

  constructor(config: OidcConfig) {
    this.config = config;
    this.jwks = createRemoteJWKSet(new URL(config.jwksUrl), {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 5 * 60_000,
    });
  }

  async checkConnection(): Promise<void> {
    if (Date.now() - this.checkedAt < 30_000) return;
    const response = await fetch(this.config.jwksUrl, {
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new Error("OIDC JWKS endpoint is unavailable");
    const payload: unknown = await response.json();
    if (
      typeof payload !== "object" ||
      payload === null ||
      !Array.isArray((payload as { keys?: unknown }).keys) ||
      (payload as { keys: unknown[] }).keys.length === 0
    ) {
      throw new Error("OIDC JWKS endpoint returned no signing keys");
    }
    this.checkedAt = Date.now();
  }

  async authenticate(authorization: string | undefined): Promise<AuthenticatedPrincipal> {
    if (!authorization || !/^Bearer\s+/i.test(authorization)) {
      throw new Error("A bearer token is required");
    }

    const token = authorization.replace(/^Bearer\s+/i, "").trim();
    if (!token || /\s/.test(token)) throw new Error("The bearer token is malformed");

    const { payload } = await jwtVerify(token, this.jwks, {
      issuer: this.config.issuer,
      audience: this.config.audience,
    });
    if (typeof payload.iss !== "string" || typeof payload.sub !== "string" || !payload.sub) {
      throw new Error("The verified token has no issuer or subject");
    }

    return { issuer: payload.iss, subject: payload.sub };
  }
}
