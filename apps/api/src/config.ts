import type { OidcConfig } from "./auth.js";
import type { SemanticJudgeConfig } from "@sieve/detector";

export type IntegrationStatus = "available" | "unavailable" | "unverified" | "not_configured";

export type ApiConfig = {
  port: number;
  databaseUrl: string | undefined;
  tatumApiKey: string | undefined;
  metricsBearerToken: string | undefined;
  semanticJudge: SemanticJudgeConfig | undefined;
  suiNetwork: "mainnet" | "testnet";
  auth: OidcConfig | undefined;
  integrations: {
    database: IntegrationStatus;
    authentication: IntegrationStatus;
    tatum: IntegrationStatus;
    walrusMemory: IntegrationStatus;
    semanticJudge: IntegrationStatus;
  };
};

function parsePort(value: string | undefined): number {
  if (value === undefined || value === "") return 3001;

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("API_PORT must be an integer between 1 and 65535");
  }
  return port;
}

function integrationStatus(configured: boolean): IntegrationStatus {
  return configured ? "unverified" : "not_configured";
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): ApiConfig {
  const network = environment.TATUM_NETWORK ?? "testnet";
  if (network !== "testnet" && network !== "mainnet") {
    throw new Error("TATUM_NETWORK must be either testnet or mainnet");
  }

  if (environment.DATABASE_URL) {
    const databaseUrl = new URL(environment.DATABASE_URL);
    if (databaseUrl.protocol !== "postgres:" && databaseUrl.protocol !== "postgresql:") {
      throw new Error("DATABASE_URL must use the postgres or postgresql protocol");
    }
  }

  const metricsBearerToken = environment.METRICS_BEARER_TOKEN;
  if (metricsBearerToken && metricsBearerToken.length < 32) {
    throw new Error("METRICS_BEARER_TOKEN must contain at least 32 characters when configured");
  }

  const judgeApiKey = environment.OPENAI_API_KEY;
  const judgeModel = environment.OPENAI_MODEL;
  const groqApiKey = environment.GROQ_API_KEY;
  const groqModel = environment.GROQ_MODEL || (groqApiKey ? "openai/gpt-oss-20b" : undefined);
  const configuredProvider = environment.SEMANTIC_JUDGE_PROVIDER;
  if (configuredProvider && !["openai", "groq", "nvidia"].includes(configuredProvider)) {
    throw new Error("SEMANTIC_JUDGE_PROVIDER must be openai, groq, or nvidia");
  }
  if (Boolean(judgeApiKey) !== Boolean(judgeModel)) {
    throw new Error("OPENAI_API_KEY and OPENAI_MODEL must be configured together");
  }
  const nvidiaApiKey = environment.NVIDIA_API_KEY;
  const nvidiaModel = environment.NVIDIA_MODEL;
  if (Boolean(nvidiaApiKey) !== Boolean(nvidiaModel)) {
    throw new Error("NVIDIA_API_KEY and NVIDIA_MODEL must be configured together");
  }
  const configuredProviders = [judgeApiKey, groqApiKey, nvidiaApiKey].filter(Boolean).length;
  if (configuredProviders > 1 && !configuredProvider) {
    throw new Error("SEMANTIC_JUDGE_PROVIDER is required when multiple judge providers are configured");
  }
  const judgeProvider = configuredProvider || (nvidiaApiKey ? "nvidia" : groqApiKey ? "groq" : judgeApiKey ? "openai" : undefined);
  if (judgeProvider === "openai" && (!judgeApiKey || !judgeModel)) {
    throw new Error("OPENAI_API_KEY and OPENAI_MODEL are required for the OpenAI semantic judge");
  }
  if (judgeProvider === "groq" && (!groqApiKey || !groqModel)) {
    throw new Error("GROQ_API_KEY and GROQ_MODEL are required for the Groq semantic judge");
  }
  if (judgeProvider === "nvidia" && (!nvidiaApiKey || !nvidiaModel)) {
    throw new Error("NVIDIA_API_KEY and NVIDIA_MODEL are required for the NVIDIA semantic judge");
  }
  if (judgeModel && (judgeModel.length > 100 || !/^[A-Za-z0-9._:-]+$/.test(judgeModel))) {
    throw new Error("OPENAI_MODEL contains unsupported characters or is too long");
  }
  if (groqModel && (groqModel.length > 100 || !/^[A-Za-z0-9._:/-]+$/.test(groqModel))) {
    throw new Error("GROQ_MODEL contains unsupported characters or is too long");
  }
  if (nvidiaModel && (nvidiaModel.length > 100 || !/^[A-Za-z0-9._:/-]+$/.test(nvidiaModel))) {
    throw new Error("NVIDIA_MODEL contains unsupported characters or is too long");
  }
  const semanticJudge = judgeProvider === "groq" && groqApiKey && groqModel
    ? { provider: "groq-responses" as const, apiKey: groqApiKey, model: groqModel, baseUrl: "https://api.groq.com/openai/v1" }
    : judgeProvider === "nvidia" && nvidiaApiKey && nvidiaModel
      ? { provider: "nvidia-nim-chat" as const, apiKey: nvidiaApiKey, model: nvidiaModel, baseUrl: "https://integrate.api.nvidia.com/v1" }
    : judgeProvider === "openai" && judgeApiKey && judgeModel
      ? { provider: "openai-responses" as const, apiKey: judgeApiKey, model: judgeModel, baseUrl: "https://api.openai.com/v1" }
    : undefined;

  const walrusServerUrl = environment.MEMWAL_SERVER_URL;
  if (walrusServerUrl) {
    const parsedWalrusUrl = new URL(walrusServerUrl);
    if (parsedWalrusUrl.protocol !== "https:" && parsedWalrusUrl.protocol !== "http:") {
      throw new Error("MEMWAL_SERVER_URL must use HTTP or HTTPS");
    }
  }

  const oidcIssuer = environment.AUTH_ISSUER;
  const oidcAudience = environment.AUTH_AUDIENCE;
  const oidcJwksUrl = environment.AUTH_JWKS_URL;
  const hasAnyOidcSetting = Boolean(oidcIssuer || oidcAudience || oidcJwksUrl);
  const hasAllOidcSettings = Boolean(oidcIssuer && oidcAudience && oidcJwksUrl);
  if (hasAnyOidcSetting && !hasAllOidcSettings) {
    throw new Error("AUTH_ISSUER, AUTH_AUDIENCE, and AUTH_JWKS_URL must be configured together");
  }

  let auth: OidcConfig | undefined;
  if (hasAllOidcSettings && oidcIssuer && oidcAudience && oidcJwksUrl) {
    const issuerUrl = new URL(oidcIssuer);
    const jwksUrl = new URL(oidcJwksUrl);
    if (issuerUrl.protocol !== "https:" || jwksUrl.protocol !== "https:") {
      throw new Error("AUTH_ISSUER and AUTH_JWKS_URL must use HTTPS");
    }
    auth = { issuer: oidcIssuer, audience: oidcAudience, jwksUrl: jwksUrl.toString() };
  }

  return {
    port: parsePort(environment.API_PORT),
    databaseUrl: environment.DATABASE_URL,
    tatumApiKey: environment.TATUM_API_KEY,
    metricsBearerToken,
    semanticJudge,
    suiNetwork: network,
    auth,
    integrations: {
      database: integrationStatus(Boolean(environment.DATABASE_URL)),
      authentication: integrationStatus(Boolean(auth)),
      tatum: integrationStatus(Boolean(environment.TATUM_API_KEY)),
      walrusMemory: integrationStatus(
        Boolean(environment.MEMWAL_ACCOUNT_ID && environment.MEMWAL_PRIVATE_KEY),
      ),
      semanticJudge: integrationStatus(Boolean(semanticJudge)),
    },
  };
}
