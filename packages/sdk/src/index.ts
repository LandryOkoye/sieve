export type SieveAction = "allow" | "review" | "block";
export type SieveFinding = {
  category: string;
  signal: string;
  strength: "strong" | "moderate";
  rationale: string;
  evidence: Record<string, unknown>;
};
export type SieveInspection = {
  id: string;
  contentHash: string;
  assessment: { outcome: "signals_detected" | "no_signals_detected" | "uncertain"; findings: SieveFinding[] };
  decision: { action: SieveAction; policyVersion: number };
  memoryEvidence: Array<{ id: string; role: "supporting_context" }>;
  memoryLearning: Array<{ id: string; status: string; storageStatus?: string }>;
  createdAt: string;
  expiresAt: string;
};

export type InspectContent = {
  content: string;
  sourceType?: string;
  sourceRef?: string;
  requestId?: string;
};

export type TrustedContextSink = {
  addTrusted(content: string): void | Promise<void>;
  quarantine?(content: string, assessment: SieveInspection): void | Promise<void>;
};

export class SieveApiError extends Error {
  constructor(message: string, readonly status: number, readonly code: string) {
    super(message);
    this.name = "SieveApiError";
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseInspection(value: unknown): SieveInspection {
  if (!isObject(value) || typeof value.id !== "string" || !/^[a-f0-9]{64}$/.test(String(value.contentHash)) ||
      !isObject(value.assessment) || !Array.isArray(value.assessment.findings) ||
      !isObject(value.decision) || !["allow", "review", "block"].includes(String(value.decision.action)) ||
      !Number.isInteger(value.decision.policyVersion) || !Array.isArray(value.memoryEvidence) || !Array.isArray(value.memoryLearning) ||
      typeof value.createdAt !== "string" || typeof value.expiresAt !== "string") {
    throw new SieveApiError("SIEVE returned an invalid inspection response", 502, "invalid_response");
  }
  const outcome = value.assessment.outcome;
  if (outcome !== "signals_detected" && outcome !== "no_signals_detected" && outcome !== "uncertain") {
    throw new SieveApiError("SIEVE returned an invalid assessment", 502, "invalid_response");
  }
  return value as unknown as SieveInspection;
}

export class SieveClient {
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;

  constructor(options: { baseUrl: string; credential: string; fetch?: typeof fetch }) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
      throw new Error("SIEVE API URL must use HTTPS outside localhost");
    }
    if (!options.credential.startsWith("sieve_live_")) throw new Error("Invalid SIEVE agent credential format");
    this.baseUrl = url.toString().replace(/\/$/, "");
    this.credential = options.credential;
    this.fetcher = options.fetch ?? fetch;
  }

  private readonly credential: string;

  async inspect(input: InspectContent): Promise<SieveInspection> {
    const requestId = input.requestId ?? crypto.randomUUID();
    let response: Response;
    try {
      response = await this.fetcher(`${this.baseUrl}/api/v1/agent/inspect`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.credential}`,
          "content-type": "application/json",
          "idempotency-key": requestId,
        },
        body: JSON.stringify({ content: input.content, ...(input.sourceType ? { sourceType: input.sourceType } : {}), ...(input.sourceRef ? { sourceRef: input.sourceRef } : {}) }),
      });
    } catch {
      throw new SieveApiError("SIEVE inspection request failed", 503, "transport_error");
    }
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const code = isObject(payload) && typeof payload.error === "string" ? payload.error : "inspection_failed";
      throw new SieveApiError("SIEVE could not assess the submitted content", response.status, code);
    }
    return parseInspection(payload);
  }

  /** Add content to trusted context only when the server policy explicitly allows it. */
  async inspectBeforeContext(input: InspectContent, context: TrustedContextSink): Promise<{ inspection: SieveInspection; addedToTrustedContext: boolean }> {
    const inspection = await this.inspect(input);
    if (inspection.decision.action === "allow") {
      await context.addTrusted(input.content);
      return { inspection, addedToTrustedContext: true };
    }
    await context.quarantine?.(input.content, inspection);
    return { inspection, addedToTrustedContext: false };
  }
}
