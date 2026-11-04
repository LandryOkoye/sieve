import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadConfig } from "./config.js";
import { Database } from "./database.js";
import { OidcAuthenticator, type AuthenticatedPrincipal } from "./auth.js";
import { TatumSuiClient, normalizeObjectId, validateTarget } from "@sieve/chain-sui";
import { detect } from "@sieve/detector";
import type { ChainFact, EvidenceBundle, InspectionCase, LookupTarget, SuiNetwork, UntrustedText } from "@sieve/contracts";

const config = loadConfig();
const database = config.databaseUrl ? new Database(config.databaseUrl) : undefined;
const authenticator = config.auth ? new OidcAuthenticator(config.auth) : undefined;
let databaseInitialized = false;
let queueWorkerBusy = false;

async function ensureDatabase(): Promise<Database> {
  if (!database) throw new Error("Database is not configured");
  if (!databaseInitialized) {
    await database.migrate();
    await database.recoverInterruptedCases();
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
  const requestUrl = new URL(request.url ?? "/", "http://localhost");
  if (request.method !== "GET" && request.method !== "POST") {
    sendJson(response, 405, { error: "method_not_allowed" });
    return;
  }

  if (request.method === "GET" && requestUrl.pathname === "/api/v1/health/live") {
    sendJson(response, 200, { status: "live" });
    return;
  }

  if (request.method === "GET" && requestUrl.pathname === "/api/v1/health/ready") {
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

  const isProtectedRoute =
    (request.method === "GET" && requestUrl.pathname === "/api/v1/me") ||
    requestUrl.pathname.startsWith("/api/v1/cases") ||
    requestUrl.pathname.startsWith("/api/v1/threat-memories");
  if (isProtectedRoute) {
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
      if (requestUrl.pathname === "/api/v1/me") {
        sendJson(response, 200, { userId });
        return;
      }
      if (request.method === "POST" && requestUrl.pathname === "/api/v1/cases") {
        let body: Record<string, unknown>;
        try {
          body = await readJsonBody(request);
        } catch {
          sendJson(response, 400, { error: "invalid_json_body" });
          return;
        }
        const parsedTarget = parseTarget(body);
        if (!parsedTarget) {
          sendJson(response, 400, { error: "invalid_case_request" });
          return;
        }
        if (!validateTarget(parsedTarget)) {
          sendJson(response, 400, { error: "invalid_sui_identifier" });
          return;
        }
        const target = parsedTarget.kind === "object"
          ? { ...parsedTarget, objectId: normalizeObjectId(parsedTarget.objectId) }
          : parsedTarget;
        const network = body.network === undefined ? config.suiNetwork : body.network;
        if (network !== "mainnet" && network !== "testnet") {
          sendJson(response, 400, { error: "invalid_network" });
          return;
        }
        const idempotencyKey = request.headers["idempotency-key"];
        if (Array.isArray(idempotencyKey) || (idempotencyKey && (idempotencyKey.length > 200 || !/^[\x20-\x7e]+$/.test(idempotencyKey)))) {
          sendJson(response, 400, { error: "invalid_idempotency_key" });
          return;
        }
        const created = await store.createCase(userId, network, target, idempotencyKey);
        if (created.created) {
          sendJson(response, 202, created.inspectionCase);
        } else {
          if (created.inspectionCase.network !== network || JSON.stringify(created.inspectionCase.target) !== JSON.stringify(target)) {
            sendJson(response, 409, { error: "idempotency_key_conflict" });
            return;
          }
          sendJson(response, 200, created.inspectionCase);
        }
        return;
      }
      const retryMatch = requestUrl.pathname.match(/^\/api\/v1\/cases\/([0-9a-f-]{36})\/retry$/i);
      if (request.method === "POST" && retryMatch) {
        const accepted = await store.retryCase(userId, retryMatch[1]!);
        if (!accepted) {
          sendJson(response, 404, { error: "retry_not_available" });
          return;
        }
        sendJson(response, 202, { id: retryMatch[1], status: "queued" });
        return;
      }
      if (request.method === "GET" && requestUrl.pathname === "/api/v1/cases") {
        const limit = parseBoundedInt(requestUrl.searchParams.get("limit"), 20, 1, 100);
        const cursorParam = requestUrl.searchParams.get("cursor");
        const cursor = cursorParam ? decodeCursor(cursorParam) : undefined;
        if (limit === null || (cursorParam && !cursor)) {
          sendJson(response, 400, { error: "invalid_pagination" });
          return;
        }
        const page = await store.listCases(userId, limit, cursor ?? undefined);
        const nextCursor = page.hasMore && page.lastCursor ? encodeCursor(page.lastCursor) : null;
        sendJson(response, 200, { cases: page.cases, limit, nextCursor });
        return;
      }
      const caseMatch = requestUrl.pathname.match(/^\/api\/v1\/cases\/([0-9a-f-]{36})$/i);
      if (request.method === "GET" && caseMatch) {
        const inspectionCase = await store.getCase(userId, caseMatch[1]!);
        sendJson(response, inspectionCase ? 200 : 404, inspectionCase ?? { error: "case_not_found" });
        return;
      }
      if (request.method === "GET" && requestUrl.pathname === "/api/v1/threat-memories") {
        const limit = parseBoundedInt(requestUrl.searchParams.get("limit"), 20, 1, 100);
        const cursorParam = requestUrl.searchParams.get("cursor");
        const cursor = cursorParam ? decodeCursor(cursorParam) : undefined;
        if (limit === null || (cursorParam && !cursor)) {
          sendJson(response, 400, { error: "invalid_pagination" });
          return;
        }
        const page = await store.listThreatMemoryWrites(userId, limit, cursor ?? undefined);
        const nextCursor = page.hasMore && page.lastCursor ? encodeCursor(page.lastCursor) : null;
        sendJson(response, 200, { memories: page.memories, limit, nextCursor });
        return;
      }
      const memoryMatch = requestUrl.pathname.match(/^\/api\/v1\/threat-memories\/([0-9a-f-]{36})$/i);
      if (request.method === "GET" && memoryMatch) {
        const memory = await store.getThreatMemoryWrite(userId, memoryMatch[1]!);
        sendJson(response, memory ? 200 : 404, memory ?? { error: "threat_memory_not_found" });
        return;
      }
      sendJson(response, 404, { error: "not_found" });
    } catch {
      sendJson(response, 503, { error: "identity_store_unavailable" });
    }
    return;
  }

  sendJson(response, 404, { error: "not_found" });
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 16_384) throw new Error("Request body too large");
    chunks.push(buffer);
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid JSON body");
  return parsed as Record<string, unknown>;
}

function parseTarget(body: Record<string, unknown>): LookupTarget | null {
  const digest = body.digest;
  const objectId = body.objectId;
  if (typeof digest === "string" && digest.length <= 64 && objectId === undefined) return { kind: "transaction", digest };
  if (typeof objectId === "string" && objectId.length <= 128 && digest === undefined) return { kind: "object", objectId };
  return null;
}

function parseBoundedInt(value: string | null, fallback: number, minimum: number, maximum: number): number | null {
  if (value === null) return fallback;
  if (!/^\d+$/.test(value)) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= minimum && number <= maximum ? number : null;
}

function encodeCursor(cursor: { createdAt: string; id: string }): string {
  return Buffer.from(JSON.stringify(cursor)).toString("base64url");
}

function decodeCursor(value: string): { createdAt: string; id: string } | null {
  if (value.length > 512 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    const cursor = parsed as { createdAt?: unknown; id?: unknown };
    if (typeof cursor.createdAt !== "string" || !Number.isFinite(Date.parse(cursor.createdAt))) return null;
    if (typeof cursor.id !== "string" || !/^[0-9a-f-]{36}$/i.test(cursor.id)) return null;
    return { createdAt: cursor.createdAt, id: cursor.id };
  } catch {
    return null;
  }
}

function protobufValueToJson(value: unknown, depth = 0): unknown {
  if (depth > 12 || !value || typeof value !== "object") return null;
  const kind = (value as { kind?: { oneofKind?: string; [key: string]: unknown } }).kind;
  if (!kind) return null;
  switch (kind.oneofKind) {
    case "stringValue": return kind.stringValue;
    case "numberValue": return kind.numberValue;
    case "boolValue": return kind.boolValue;
    case "structValue": {
      const fields = (kind.structValue as { fields?: Record<string, unknown> } | undefined)?.fields;
      if (!fields) return null;
      return Object.fromEntries(Object.entries(fields).slice(0, 200).map(([key, child]) => [key, protobufValueToJson(child, depth + 1)]));
    }
    case "listValue": {
      const values = (kind.listValue as { values?: unknown[] } | undefined)?.values;
      return values?.slice(0, 200).map((child) => protobufValueToJson(child, depth + 1)) ?? [];
    }
    default: return null;
  }
}

function collectText(value: unknown, field: string, evidence: UntrustedText["evidence"], output: UntrustedText[], depth = 0): void {
  if (output.length >= 200 || depth > 12) return;
  if (typeof value === "string") {
    if (value.length && output.length < 200) output.push({ field, value: value.slice(0, 4_000), evidence });
  } else if (Array.isArray(value)) {
    value.slice(0, 200).forEach((child, index) => collectText(child, `${field}[${index}]`, evidence, output, depth + 1));
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value).slice(0, 200)) collectText(child, `${field}.${key}`, evidence, output, depth + 1);
  }
}

function addFact(facts: ChainFact[], field: string, value: string | number | boolean | null, evidence: ChainFact["evidence"]): void {
  if (value !== null && value !== undefined) facts.push({ field, value, evidence });
}

async function processCase(store: Database, userId: string, inspectionCase: InspectionCase, network: SuiNetwork): Promise<InspectionCase> {
  if (!config.tatumApiKey) {
    await store.updateCaseStatus(userId, inspectionCase.id, "failed", undefined, "tatum_not_configured");
    return (await store.getCase(userId, inspectionCase.id))!;
  }
  await store.updateCaseStatus(userId, inspectionCase.id, "fetching_evidence");
  const client = new TatumSuiClient({ apiKey: config.tatumApiKey, network });
  try {
    const facts: ChainFact[] = [];
    const untrustedText: UntrustedText[] = [];
    const warnings: string[] = [];
    let completeness: EvidenceBundle["completeness"] = "complete";
    let providerMethod: string;
    if (inspectionCase.target.kind === "object") {
      providerMethod = "ledgerService.getObject";
      const object = await client.getObject(inspectionCase.target.objectId) as any;
      const evidence = { objectId: inspectionCase.target.objectId };
      addFact(facts, "objectId", object.objectId ?? null, evidence);
      addFact(facts, "version", object.version === undefined ? null : String(object.version), evidence);
      addFact(facts, "digest", object.digest ?? null, evidence);
      addFact(facts, "objectType", object.objectType ?? null, evidence);
      const json = object.json ? protobufValueToJson(object.json) : null;
      if (json) collectText(json, "object.json", evidence, untrustedText);
      else {
        completeness = "partial";
        warnings.push("Object JSON metadata was not returned; BCS contents were not decoded.");
      }
      const display = object.display?.output ? protobufValueToJson(object.display.output) : null;
      if (display) collectText(display, "object.display", evidence, untrustedText);
    } else {
      providerMethod = "ledgerService.getTransaction";
      completeness = "partial";
      warnings.push("Transaction command arguments and BCS-only fields were not decoded; text extraction may be incomplete.");
      const transaction = await client.getTransaction(inspectionCase.target.digest) as any;
      const evidence = { digest: inspectionCase.target.digest };
      addFact(facts, "digest", transaction.digest ?? null, evidence);
      addFact(facts, "checkpoint", transaction.checkpoint === undefined ? null : String(transaction.checkpoint), evidence);
      addFact(facts, "timestampSeconds", transaction.timestamp?.seconds === undefined ? null : String(transaction.timestamp.seconds), evidence);
      addFact(facts, "executionStatus", transaction.effects?.status?.success ?? null, evidence);
      const events = transaction.events?.events ?? [];
      for (const [index, event] of events.entries()) {
        const pointer = { ...evidence, eventIndex: event.eventIndex ?? index };
        addFact(facts, `events[${index}].eventType`, event.eventType ?? null, pointer);
        addFact(facts, `events[${index}].packageId`, event.packageId ?? null, pointer);
        if (event.json) collectText(protobufValueToJson(event.json), `events[${index}].json`, pointer, untrustedText);
        else completeness = "partial";
      }
      const objects = transaction.objects?.objects ?? [];
      for (const [index, object] of objects.entries()) {
        const pointer = { objectId: object.objectId ?? undefined, digest: inspectionCase.target.digest };
        addFact(facts, `objects[${index}].objectType`, object.objectType ?? null, pointer);
        if (object.json) collectText(protobufValueToJson(object.json), `objects[${index}].json`, pointer, untrustedText);
      }
      if (!transaction.effects || !transaction.events || !transaction.objects) {
        completeness = "partial";
        warnings.push("The provider returned incomplete transaction effects, events, or object details.");
      }
    }
    if (untrustedText.length >= 200 || untrustedText.some((item) => item.value.length >= 4_000)) {
      completeness = "partial";
      warnings.push("Some on-chain text was truncated to enforce evidence size limits.");
    }
    const bundle: EvidenceBundle = { network, target: inspectionCase.target, retrievedAt: new Date().toISOString(), provider: "tatum-sui-grpc", providerMethod, completeness, facts, untrustedText, warnings };
    await store.updateCaseStatus(userId, inspectionCase.id, "assessing", bundle);
    await store.saveAssessment(userId, inspectionCase.id, detect(untrustedText, completeness));
  } catch {
    await store.updateCaseStatus(userId, inspectionCase.id, "failed", undefined, "evidence_provider_unavailable");
  } finally {
    client.close();
  }
  return (await store.getCase(userId, inspectionCase.id))!;
}

const server = createServer((request, response) => {
  void handleRequest(request, response).catch(() => {
    sendJson(response, 500, { error: "internal_error" });
  });
});

async function runQueueWorker(): Promise<void> {
  if (queueWorkerBusy || !database) return;
  queueWorkerBusy = true;
  try {
    const store = await ensureDatabase();
    const claimed = await store.claimNextCase();
    if (claimed) await processCase(store, claimed.userId, claimed.inspectionCase, claimed.inspectionCase.network);
  } catch {
    process.stderr.write("Case queue worker could not process its next item.\n");
  } finally {
    queueWorkerBusy = false;
  }
}

const queueWorker = setInterval(() => { void runQueueWorker(); }, 1_000);
queueWorker.unref();

server.listen(config.port, "0.0.0.0", () => {
  process.stdout.write(`SIEVE API listening on port ${config.port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    clearInterval(queueWorker);
    server.close(() => {
      void database?.close();
    });
  });
}
