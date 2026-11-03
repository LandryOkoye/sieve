import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadConfig } from "./config.js";
import { Database } from "./database.js";
import { OidcAuthenticator, type AuthenticatedPrincipal } from "./auth.js";

const config = loadConfig();
const database = config.databaseUrl ? new Database(config.databaseUrl) : undefined;
const authenticator = config.auth ? new OidcAuthenticator(config.auth) : undefined;
let databaseInitialized = false;

async function ensureDatabase(): Promise<Database> {
  if (!database) throw new Error("Database is not configured");
  if (!databaseInitialized) {
    await database.migrate();
    databaseInitialized = true;
  }
  await database.checkConnection();
  return database;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "method_not_allowed" });
    return;
  }

  if (request.url === "/api/v1/health/live") {
    sendJson(response, 200, { status: "live" });
    return;
  }

  if (request.url === "/api/v1/health/ready") {
    const integrations = { ...config.integrations };
    if (database) {
      try {
        await ensureDatabase();
        integrations.database = "available";
      } catch {
        databaseInitialized = false;
        integrations.database = "unavailable";
      }
    }
    if (authenticator) {
      try {
        await authenticator.checkConnection();
        integrations.authentication = "available";
      } catch {
        integrations.authentication = "unavailable";
      }
    }
    const ready = Object.values(integrations).every((status) => status === "available");
    sendJson(response, ready ? 200 : 503, {
      status: ready ? "ready" : "not_ready",
      integrations,
    });
    return;
  }

  if (request.url === "/api/v1/me") {
    if (!authenticator) {
      sendJson(response, 503, { error: "authentication_not_configured" });
      return;
    }
    let principal: AuthenticatedPrincipal;
    try {
      principal = await authenticator.authenticate(request.headers.authorization);
    } catch {
      try {
        await authenticator.checkConnection();
      } catch {
        sendJson(response, 503, { error: "authentication_provider_unavailable" });
        return;
      }
      sendJson(response, 401, { error: "unauthenticated" });
      return;
    }
    try {
      const store = await ensureDatabase();
      const userId = await store.resolveUserId(principal.issuer, principal.subject);
      sendJson(response, 200, { userId });
    } catch {
      sendJson(response, 503, { error: "identity_store_unavailable" });
    }
    return;
  }

  sendJson(response, 404, { error: "not_found" });
}

const server = createServer((request, response) => {
  void handleRequest(request, response).catch(() => {
    sendJson(response, 500, { error: "internal_error" });
  });
});

server.listen(config.port, "0.0.0.0", () => {
  process.stdout.write(`SIEVE API listening on port ${config.port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => {
      void database?.close();
    });
  });
}
