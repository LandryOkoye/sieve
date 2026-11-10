import { createHash } from "node:crypto";
import type { DetectorVerdict, UntrustedText } from "@sieve/contracts";
import type { ProtectedAgent, DirectInspectionInput, StoredDirectInspection } from "./database.js";
import type { InspectionAction } from "./inspection.js";
import { assessDirectContent } from "./inspection.js";
import type { ThreatMemory } from "@sieve/threat-memory/lifecycle";

export type AgentInspectionStore = {
  authenticateAgent(tokenHash: string, requiredScope: string): Promise<ProtectedAgent | null>;
  saveDirectInspection(input: DirectInspectionInput): Promise<{ inspection: StoredDirectInspection; created: boolean } | { conflict: true }>;
};
type Reply = { status: number; body: Record<string, unknown> };

function selectedAction(agent: ProtectedAgent, verdict: DetectorVerdict): InspectionAction {
  const policy = agent.policy;
  const configured = (key: string, fallback: InspectionAction, allowed: readonly InspectionAction[]) => {
    const value = policy[key];
    return typeof value === "string" && allowed.includes(value as InspectionAction) ? value as InspectionAction : fallback;
  };
  if (verdict.findings.some((finding) => finding.strength === "strong")) return "block";
  if (verdict.findings.length) return configured("onSignal", "review", ["review", "block"]);
  if (verdict.outcome === "uncertain") return configured("onUncertain", "review", ["review", "block"]);
  return configured("onClean", "allow", ["allow", "review", "block"]);
}

export async function inspectForAgent(input: {
  store: AgentInspectionStore;
  tokenHash: string;
  requestId: string;
  body: Record<string, unknown>;
  now?: string;
  recall?: (query: string, agent: ProtectedAgent) => Promise<readonly unknown[]>;
  semanticReview?: (items: readonly UntrustedText[], memories: readonly ThreatMemory[]) => Promise<{ findings: DetectorVerdict["findings"]; complete: boolean }>;
  afterAssessment?: (input: { inspectionId: string; agent: ProtectedAgent; contentHash: string; sourceType: string; at: string; findings: DetectorVerdict["findings"] }) => Promise<readonly { id: string; status: string; storageStatus?: string }[]>;
}): Promise<Reply> {
  const content = input.body.content;
  const sourceType = input.body.sourceType ?? "direct_content";
  const sourceRef = input.body.sourceRef;
  if (Object.keys(input.body).some((key) => !["content", "sourceType", "sourceRef"].includes(key)) ||
      typeof content !== "string" || !content.trim() || Buffer.byteLength(content, "utf8") > 65_536 ||
      typeof sourceType !== "string" || !/^[a-z][a-z0-9_]{1,79}$/.test(sourceType) ||
      (sourceRef !== undefined && (typeof sourceRef !== "string" || sourceRef.length > 2_048)) ||
      !/^[\x20-\x7e]{1,200}$/.test(input.requestId)) {
    return { status: 400, body: { error: "invalid_inspection_request" } };
  }
  const agent = await input.store.authenticateAgent(input.tokenHash, "inspect");
  if (!agent) return { status: 401, body: { error: "invalid_agent_credential" } };

  const contentHash = createHash("sha256").update(content).digest("hex");
  const sourceRefHash = typeof sourceRef === "string" ? createHash("sha256").update(sourceRef).digest("hex") : null;
  const inspectedAt = input.now ?? new Date().toISOString();
  const textItems: UntrustedText[] = [{
    field: sourceType,
    value: content,
    evidence: { contentSha256: contentHash },
  }];
  const includeGlobal = agent.policy.includeGlobalMemory === true;
  const assessment = await assessDirectContent({
    textItems,
    completeness: "complete",
    scope: { workspaceId: agent.workspaceId, agentId: agent.id, includeGlobal },
    now: inspectedAt,
    recall: (query) => input.recall ? input.recall(query, agent) : Promise.resolve([]),
    ...(input.semanticReview ? { semanticReview: input.semanticReview } : {}),
  });
  const action = selectedAction(agent, assessment.verdict);
  const stored = await input.store.saveDirectInspection({
    agentId: agent.id,
    workspaceId: agent.workspaceId,
    requestId: input.requestId,
    contentHash,
    contentBytes: Buffer.byteLength(content, "utf8"),
    sourceType,
    sourceRefHash,
    outcome: assessment.verdict.outcome,
    action,
    findings: assessment.verdict.findings,
    memoryIds: assessment.memories.map((memory) => memory.id),
    detectorVersion: input.semanticReview ? "rules-v3+semantic" : "rules-v3",
    policyVersion: agent.policyVersion,
  });
  if ("conflict" in stored) return { status: 409, body: { error: "idempotency_key_conflict" } };
  const memoryLearning = input.afterAssessment
    ? await input.afterAssessment({ inspectionId: stored.inspection.id, agent, contentHash, sourceType, at: inspectedAt, findings: stored.inspection.findings })
    : [];

  return {
    status: stored.created ? 201 : 200,
    body: {
      id: stored.inspection.id,
      contentHash,
      assessment: { outcome: stored.inspection.outcome, findings: stored.inspection.findings },
      decision: { action: stored.inspection.action, policyVersion: agent.policyVersion },
      memoryEvidence: stored.inspection.memoryIds.map((id) => ({ id, role: "supporting_context" })),
      memoryLearning,
      createdAt: stored.inspection.createdAt,
      expiresAt: stored.inspection.expiresAt,
    },
  };
}
