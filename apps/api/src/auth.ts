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

  constructor(config: OidcConfig) {
    this.config = config;
    this.jwks = createRemoteJWKSet(new URL(config.jwksUrl), {
      timeoutDuration: 5_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 5 * 60_000,
    });
  }

  async authenticate(authorization: string | undefined): Promise<AuthenticatedPrincipal> {
    if (!authorization?.startsWith("Bearer ")) {
      throw new Error("A bearer token is required");
    }

    const token = authorization.slice("Bearer ".length).trim();
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
