import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadConfig } from "./config.js";
import { Database } from "./database.js";

const config = loadConfig();
const database = config.databaseUrl ? new Database(config.databaseUrl) : undefined;
let databaseInitialized = false;

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
        if (!databaseInitialized) {
          await database.migrate();
          databaseInitialized = true;
        }
        await database.checkConnection();
        integrations.database = "available";
      } catch {
        databaseInitialized = false;
        integrations.database = "unavailable";
      }
    }
    const ready = Object.values(integrations).every((status) => status === "available");
    sendJson(response, ready ? 200 : 503, {
      status: ready ? "ready" : "not_ready",
      integrations,
    });
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
