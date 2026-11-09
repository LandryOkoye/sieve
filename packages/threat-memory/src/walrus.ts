import { MemWal } from "@mysten-incubation/memwal";
import type { ThreatCategory } from "@sieve/detector";
import type { MemoryWriteDecision, ThreatMemoryRecord } from "./policy.js";
import { parseThreatMemory as parseLifecycleThreatMemory, type MemoryRecallScope, type ThreatMemory, type ThreatMemoryScope } from "./lifecycle.js";

type MemWalClient = ReturnType<typeof MemWal.create>;

export type WalrusMemoryConfig = {
  accountId: string;
  delegateKey: string;
  serverUrl: string;
  namespace: string;
};

export type RecalledThreatMemory = {
  record: ThreatMemoryRecord;
  blobId: string;
  distance: number;
  trust: "untrusted_memory";
};

export type ThreatMemoryRecall = {
  records: RecalledThreatMemory[];
  rejected: Array<{ blobId: string; reason: "invalid_record_schema" }>;
};

export type LifecycleMemoryHit = {
  memory: ThreatMemory;
  blobId: string;
  distance: number;
  namespace: string;
};

export type WalrusBlobMetadata = { endEpoch: number | null; expiresAt: string | null };

export async function namespaceForThreatScope(base: string, scope: ThreatMemoryScope): Promise<string> {
  if (!/^[a-zA-Z0-9._-]{1,120}$/.test(base)) throw new Error("invalid_walrus_namespace");
  if (scope.kind === "global") return `${base}-v1-global`;
  const source = scope.kind === "workspace" ? `workspace:${scope.workspaceId}` : `agent:${scope.workspaceId}:${scope.agentId}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(source));
  const suffix = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 32);
  return `${base}-v1-${scope.kind}-${suffix}`;
}

const categories = new Set<ThreatCategory>([
  "instruction_override",
  "trust_manipulation",
  "recommendation_steering",
  "memory_manipulation",
]);

const patterns: Record<ThreatCategory, ReadonlySet<string>> = {
  instruction_override: new Set(["instruction_override_language"]),
  trust_manipulation: new Set(["unsupported_trust_claim"]),
  recommendation_steering: new Set(["direct_recommendation_command"]),
  memory_manipulation: new Set(["memory_write_instruction"]),
};

const summaries: Record<ThreatCategory, string> = {
  instruction_override: "Chain text attempted to replace or ignore an agent's existing instructions.",
  trust_manipulation: "Chain text asserted trust or verification without independent supporting evidence.",
  recommendation_steering: "Chain text attempted to control an agent's recommendations or concealment.",
  memory_manipulation: "Chain text attempted to make an agent retain a claim, rule, or instruction.",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function parseThreatMemory(value: unknown): ThreatMemoryRecord | undefined {
  if (!isRecord(value) || !hasOnlyKeys(value, ["schemaVersion", "category", "pattern", "summary", "source"])) {
    return undefined;
  }
  if (value.schemaVersion !== 1 || typeof value.category !== "string" || !categories.has(value.category as ThreatCategory)) {
    return undefined;
  }
  if (typeof value.pattern !== "string" || typeof value.summary !== "string" || !isRecord(value.source)) {
    return undefined;
  }

  const source = value.source;
  if (!hasOnlyKeys(source, ["network", "target", "providerMethod", "retrievedAt", "field", "evidence"])) {
    return undefined;
  }
  if (
    (source.network !== "mainnet" && source.network !== "testnet") ||
    typeof source.providerMethod !== "string" ||
    typeof source.retrievedAt !== "string" ||
    typeof source.field !== "string" ||
    !isRecord(source.target) ||
    !isRecord(source.evidence)
  ) {
    return undefined;
  }

  const target = source.target;
  const evidence = source.evidence;
  if (!hasOnlyKeys(target, ["kind", "digest", "objectId"]) || !hasOnlyKeys(evidence, ["digest", "objectId", "eventIndex"])) {
    return undefined;
  }
  if (target.kind === "transaction") {
    if (typeof target.digest !== "string" || "objectId" in target) return undefined;
  } else if (target.kind === "object") {
    if (typeof target.objectId !== "string" || "digest" in target) return undefined;
  } else {
    return undefined;
  }
  if (
    (evidence.digest !== undefined && typeof evidence.digest !== "string") ||
    (evidence.objectId !== undefined && typeof evidence.objectId !== "string") ||
    (evidence.eventIndex !== undefined &&
      (typeof evidence.eventIndex !== "number" ||
        !Number.isInteger(evidence.eventIndex) ||
        evidence.eventIndex < 0)) ||
    (!evidence.digest && !evidence.objectId) ||
    Number.isNaN(Date.parse(source.retrievedAt))
  ) {
    return undefined;
  }

  const category = value.category as ThreatCategory;
  if (!patterns[category].has(value.pattern) || value.summary !== summaries[category]) return undefined;
  if (
    (target.kind === "transaction" && evidence.digest !== target.digest) ||
    (target.kind === "object" && evidence.objectId !== target.objectId)
  ) {
    return undefined;
  }

  return value as unknown as ThreatMemoryRecord;
}

export class WalrusThreatMemory {
  private readonly namespace: string;
  private readonly client: MemWalClient;

  constructor(config: WalrusMemoryConfig, client?: MemWalClient) {
    this.namespace = config.namespace;
    this.client = client ?? MemWal.create({
      key: config.delegateKey,
      accountId: config.accountId,
      serverUrl: config.serverUrl,
      namespace: config.namespace,
    });
  }

  async checkConnection(): Promise<void> {
    await this.client.health();
  }

  async store(decision: MemoryWriteDecision) {
    if (!decision.allowed) throw new Error("Threat memory write was rejected by SIEVE policy");
    return this.client.rememberAndWait(JSON.stringify(decision.record), this.namespace, { dedupe: true });
  }

  async recall(query: string, limit = 10): Promise<ThreatMemoryRecall> {
    if (!query.trim()) throw new Error("Threat memory recall requires a non-empty query");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("Threat memory recall limit must be between 1 and 100");
    }
    const result = await this.client.recall({ query, limit, namespace: this.namespace });
    const records: RecalledThreatMemory[] = [];
    const rejected: ThreatMemoryRecall["rejected"] = [];

    for (const item of result.results) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(item.text);
      } catch {
        rejected.push({ blobId: item.blob_id, reason: "invalid_record_schema" });
        continue;
      }

      const record = parseThreatMemory(parsed);
      if (!record) {
        rejected.push({ blobId: item.blob_id, reason: "invalid_record_schema" });
        continue;
      }
      records.push({
        record,
        blobId: item.blob_id,
        distance: item.distance,
        trust: "untrusted_memory",
      });
    }

    return { records, rejected };
  }

  async storeLifecycleRecord(record: ThreatMemory): Promise<{ jobId: string; blobId: string; namespace: string; metadata: WalrusBlobMetadata | null }> {
    const namespace = await namespaceForThreatScope(this.namespace, record.scope);
    const result = await this.client.rememberAndWait(JSON.stringify(record), namespace, { dedupe: true });
    const metadata = await this.findBlobMetadata(result.blob_id, namespace);
    return { jobId: result.job_id ?? result.id, blobId: result.blob_id, namespace, metadata };
  }

  async recallLifecycleRecords(query: string, scope: MemoryRecallScope, limit = 8): Promise<LifecycleMemoryHit[]> {
    if (!query.trim() || query.length > 512) throw new Error("invalid_walrus_recall_query");
    if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new Error("invalid_walrus_recall_limit");
    const scopes: ThreatMemoryScope[] = [
      { kind: "agent", workspaceId: scope.workspaceId, agentId: scope.agentId },
      { kind: "workspace", workspaceId: scope.workspaceId },
      ...(scope.includeGlobal ? [{ kind: "global" } as const] : []),
    ];
    const results = await Promise.all(scopes.map(async (memoryScope) => {
      const namespace = await namespaceForThreatScope(this.namespace, memoryScope);
      const recalled = await this.client.recall({ query, limit, namespace });
      return recalled.results.flatMap((item) => {
        try {
          const memory = parseLifecycleThreatMemory(JSON.parse(item.text));
          return memory ? [{ memory, blobId: item.blob_id, distance: item.distance, namespace }] : [];
        } catch {
          return [];
        }
      });
    }));
    return results.flat().sort((left, right) => left.distance - right.distance).slice(0, limit);
  }

  private async findBlobMetadata(blobId: string, namespace: string): Promise<WalrusBlobMetadata | null> {
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const inventory = await this.client.listMemories({ namespace, limit: 500, ...(cursor ? { cursor } : {}) });
      const match = inventory.memories.find((memory) => memory.blob_id === blobId);
      if (match) return {
        endEpoch: Number.isInteger(match.end_epoch) ? match.end_epoch : null,
        expiresAt: typeof match.expires_at === "string" && Number.isFinite(Date.parse(match.expires_at)) ? match.expires_at : null,
      };
      if (!inventory.has_more || !inventory.next_cursor) break;
      cursor = inventory.next_cursor;
    }
    return null;
  }
}
