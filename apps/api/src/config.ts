export type IntegrationStatus = "available" | "unavailable" | "unverified" | "not_configured";

export type ApiConfig = {
  port: number;
  databaseUrl: string | undefined;
  integrations: {
    database: IntegrationStatus;
    tatum: IntegrationStatus;
    walrusMemory: IntegrationStatus;
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

  const walrusServerUrl = environment.MEMWAL_SERVER_URL;
  if (walrusServerUrl) {
    const parsedWalrusUrl = new URL(walrusServerUrl);
    if (parsedWalrusUrl.protocol !== "https:" && parsedWalrusUrl.protocol !== "http:") {
      throw new Error("MEMWAL_SERVER_URL must use HTTP or HTTPS");
    }
  }

  return {
    port: parsePort(environment.API_PORT),
    databaseUrl: environment.DATABASE_URL,
    integrations: {
      database: integrationStatus(Boolean(environment.DATABASE_URL)),
      tatum: integrationStatus(Boolean(environment.TATUM_API_KEY)),
      walrusMemory: integrationStatus(
        Boolean(environment.MEMWAL_ACCOUNT_ID && environment.MEMWAL_PRIVATE_KEY),
      ),
    },
  };
}
