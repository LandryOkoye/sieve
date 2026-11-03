import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const port = Number(process.env.API_PORT ?? 3001);
const requiredIntegrations = ["DATABASE_URL", "TATUM_API_KEY", "MEMWAL_ACCOUNT_ID", "MEMWAL_PRIVATE_KEY"];

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

function handleRequest(request: IncomingMessage, response: ServerResponse): void {
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "method_not_allowed" });
    return;
  }

  if (request.url === "/api/v1/health/live") {
    sendJson(response, 200, { status: "live" });
    return;
  }

  if (request.url === "/api/v1/health/ready") {
    sendJson(response, 503, {
      status: "not_ready",
      integrations: requiredIntegrations.map((name) => ({
        name,
        status: process.env[name] ? "unverified" : "not_configured",
      })),
    });
    return;
  }

  sendJson(response, 404, { error: "not_found" });
}

const server = createServer(handleRequest);

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`SIEVE API listening on port ${port}\n`);
});
