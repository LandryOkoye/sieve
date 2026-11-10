import { isIsoDate, type ThreatMemory, type ThreatMemoryStatus } from "./records.js";

export type MemoryReviewer = {
  userId: string;
  workspaceIds: readonly string[];
  canReviewGlobal: boolean;
};

export type MemoryReviewAction = "validate" | "promote" | "reject" | "mark_false_positive" | "revoke" | "supersede";
export type MemoryReviewDetails = {
  rationale: string;
  privacyReviewed?: boolean;
  corroboratingWorkspaceIds?: readonly string[];
};

export type MemoryReviewResult =
  | {
      ok: true;
      memory: ThreatMemory;
      event: { action: MemoryReviewAction; reviewerId: string; rationale: string; at: string };
    }
  | {
      ok: false;
      reason: "not_authorized" | "invalid_transition" | "review_rationale_required" | "global_validation_requirements_missing";
    };

function reviewerCanAccess(memory: ThreatMemory, reviewer: MemoryReviewer): boolean {
  if (memory.scope.kind === "global") return reviewer.canReviewGlobal;
  return reviewer.workspaceIds.includes(memory.scope.workspaceId);
}

/** Apply an authorized, auditable lifecycle transition without mutating the input record. */
export function reviewThreatMemory(
  memory: ThreatMemory,
  action: MemoryReviewAction,
  reviewer: MemoryReviewer,
  details: MemoryReviewDetails,
  at: string,
): MemoryReviewResult {
  const rationale = details.rationale.trim();
  if (rationale.length < 12 || rationale.length > 500 || !isIsoDate(at)) {
    return { ok: false, reason: "review_rationale_required" };
  }
  if (!reviewerCanAccess(memory, reviewer)) return { ok: false, reason: "not_authorized" };
  const validation = memory.validation;
  let status: ThreatMemoryStatus;
  let nextValidation = validation;

  if (action === "validate" && memory.status === "candidate") {
    const corroboratingWorkspaceIds = [...new Set(details.corroboratingWorkspaceIds ?? [])];
    if (memory.scope.kind === "global" && (details.privacyReviewed !== true || corroboratingWorkspaceIds.length < 2)) {
      return { ok: false, reason: "global_validation_requirements_missing" };
    }
    status = "validated";
    nextValidation = {
      reviewerId: reviewer.userId,
      reviewedAt: at,
      rationale,
      privacyReviewed: details.privacyReviewed === true,
      corroboratingWorkspaceIds,
    };
  } else if (action === "promote" && memory.status === "validated" && validation) {
    if (memory.scope.kind === "global" && (!reviewer.canReviewGlobal || !validation.privacyReviewed || validation.corroboratingWorkspaceIds.length < 2)) {
      return { ok: false, reason: "global_validation_requirements_missing" };
    }
    status = "active";
  } else if (action === "reject" && (memory.status === "candidate" || memory.status === "validated")) {
    status = "rejected";
  } else if (action === "mark_false_positive" && !["rejected", "false_positive", "superseded"].includes(memory.status)) {
    status = "false_positive";
  } else if (action === "revoke" && !["rejected", "false_positive", "revoked", "superseded"].includes(memory.status)) {
    status = "revoked";
  } else if (action === "supersede" && memory.status === "active") {
    status = "superseded";
  } else {
    return { ok: false, reason: "invalid_transition" };
  }

  return {
    ok: true,
    memory: { ...memory, status, validation: nextValidation, updatedAt: at },
    event: { action, reviewerId: reviewer.userId, rationale, at },
  };
}

/** Return true only for active, unexpired memory in a scope authorized for this inspection. */
