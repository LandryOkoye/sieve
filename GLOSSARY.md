# SIEVE

SIEVE is agent-defense infrastructure that inspects untrusted external content, preserves evidence and provenance, applies a policy, and uses reviewed threat knowledge to inform later inspections. Sui is the first blockchain evidence source, not the product boundary.

## Runtime inspection

**Protected agent**: An external AI agent registered with SIEVE and authorized through a scoped credential and policy.

**Inspection**: A request to assess untrusted content and its source provenance before the integrating agent uses that content.

**Evidence**: The submitted content hash, source metadata, normalized source facts, and references that support an assessment. Chain evidence does not prove natural-language claims are true.

**Finding**: An explained detector signal tied to inspected content or source evidence.

**Detection status**: The detector's result (`NO_SIGNAL`, `SIGNALS_DETECTED`, `INCONCLUSIVE`, or `INSPECTION_FAILED`), independent of what policy tells the caller to do.

**Enforcement action**: The policy result (`ALLOW`, `QUARANTINE`, or `REVIEW`). SIEVE reports an action; the integrating agent must enforce it.

**Untrusted content**: External text or recalled data that remains data and never becomes privileged instructions, whether or not a signal is found.

## Defensive memory

**Threat memory**: A minimized, SIEVE-authored, provenance-backed record of a manipulation technique. It does not contain raw private conversation or attacker instructions as trusted knowledge.

**Candidate memory**: A newly recorded observation awaiting an authorized review. It cannot influence inspection decisions.

**Validated memory**: A candidate approved by an authorized reviewer with its evidence, scope, rationale, and review event recorded.

**Active memory**: A validated record explicitly promoted for supporting recall within its authorized scope. It never overrides fresh evidence or policy.

**Memory scope**: `agent`, `workspace`, or `global`. Global knowledge requires a designated global reviewer; workspace and agent data remain isolated.

**Recalled memory**: An untrusted Walrus result that SIEVE must match to PostgreSQL lifecycle, scope, provenance, integrity, and expiry metadata before use.

**Assessment revision**: A persisted result under a particular detector, policy version, evidence set, and recalled-memory set.
