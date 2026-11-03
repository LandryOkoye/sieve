import { MemWal } from "@mysten-incubation/memwal";
import type { ThreatCategory } from "@sieve/detector";
import type { MemoryWriteDecision, ThreatMemoryRecord } from "./policy.js";

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
  private readonly client: ReturnType<typeof MemWal.create>;

  constructor(config: WalrusMemoryConfig) {
    this.namespace = config.namespace;
    this.client = MemWal.create({
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
    return this.client.rememberAndWait(JSON.stringify(decision.record), this.namespace);
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
}
