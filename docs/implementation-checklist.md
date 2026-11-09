# SIEVE implementation checklist

This checklist follows [ADR 0001](adr/0001-typescript-modular-monolith.md) and the product blueprint. Keep backend changes on `core`; coordinate shared REST contracts with the `frontend` owner. Do not replace the compiled frontend artifact until its source and package manifest have been located.

## Runtime inspection order

- [ ] Authenticate the external agent with a scoped, revocable credential and resolve its workspace, agent, policy, limits, and permitted memory scopes. (One-time credential provisioning and inspection authentication are implemented; rotation/revocation endpoints and limits pending.)
- [ ] Validate and normalize the request. Direct content must be inspectable without Tatum. Preserve source provenance and correlation ID without requiring a private system prompt or conversation. (Direct HTTP route implemented; source references are hashed.)
- [ ] Run initial deterministic detection before the final assessment. Record findings, evidence spans, detector version, and incomplete coverage.
- [ ] Derive a minimized retrieval query from detector features. Do not send submitted raw content, hidden prompts, conversation history, credentials, or sensitive context to Walrus.
- [ ] Recall a bounded set of memories from the agent and workspace scopes; include global scope only when policy enables it.
- [ ] Validate every recalled record against the PostgreSQL memory ID, scope, workspace/agent authorization, schema version, integrity/hash, lifecycle status, provenance, expiry, and retention state. Exclude candidates, rejected, false-positive, revoked, superseded, malformed, expired, and unauthorized records. (Database-authoritative validation method and source-inspection FK are implemented; API wiring pending.)
- [ ] Treat recalled records as untrusted supporting evidence. They may add context or raise review, but may not remove current findings, supply missing source evidence, override policy, or independently force a decision.
- [ ] If configured and warranted, run semantic review over bounded inspected content and selected structured memory features as untrusted data. Require schema-valid structured output. The model cannot promote memory, change policy, access tools, or execute actions.
- [ ] Make the final explainable assessment and policy action only after initial detection and eligible recall. Keep detection status separate from `ALLOW`, `QUARANTINE`, and `REVIEW`; represent inconclusive and failed inspection explicitly.
- [ ] Persist the assessment, evidence references, memory contribution, and audit event before returning the result.
- [ ] Create a candidate memory only from a policy-eligible finding. Never automatically promote it because of a detector or model result.

## Threat-memory lifecycle and authorization

- [ ] Store typed, versioned, minimized records with category/technique, SIEVE-authored summary, behavioral features, safe fingerprint, source/evidence hashes, confidence rationale, scope, timestamps, Walrus reference, and expiry metadata.
- [ ] Support `candidate → validated → active`, with terminal or non-retrievable `rejected`, `false_positive`, `revoked`, and `superseded` states.
- [ ] Require an authenticated reviewer authorized for the record's scope to validate and separately promote a candidate. Persist reviewer identity, action, rationale, and timestamp.
- [ ] Workspace reviewers can review only their workspace records. Agent-private records require the owning workspace's authorized reviewer. Cross-workspace reads and writes must fail closed.
- [ ] Global promotion requires an explicitly configured global reviewer and documented privacy/provenance checks. Global records are read-only to workspace users and remain supporting evidence.
- [ ] Use separate, deterministic Walrus namespaces for global, workspace, and agent scopes. Enforce authorization in PostgreSQL and the API as well: a namespace is not an onchain authorization boundary. (Namespace adapter exists; PostgreSQL-authoritative recall filter remains pending.)
- [ ] Add tests proving that a candidate cannot influence recall, a rejected/revoked record cannot influence assessment, and cross-workspace memory is never returned.

## Walrus privacy, access, and retention

- [ ] Send only minimized, SIEVE-authored threat features and evidence hashes/references. Never store private conversation text, system/developer prompts, API keys, credentials, secrets, or unrelated personal data.
- [ ] Do not treat blob IDs as secrets. Keep API and delegate keys server-side and out of logs, responses, memory records, and fixtures.
- [ ] Verify the configured relayer, Walrus Memory SDK/relayer compatibility, owner/account, delegate authorization, namespace behavior, encryption mode, and live signed read/write behavior before marking the integration available.
- [ ] The current locked MemWal SDK is 0.1.12. In its default relayer-backed mode, the relayer receives plaintext for embedding and encryption before Walrus upload; select this mode only for the minimized threat record and document the relayer trust assumption.
- [ ] Track Walrus `blob_id`, write/index status, `end_epoch`/`expires_at` where exposed, and last successful reconciliation in PostgreSQL. Treat `remember()` acceptance as pending; wait for confirmed storage/indexing before reporting success. (Adapter confirms with `rememberAndWait` and queries inventory; persistence/reconciliation remains pending.)
- [ ] Verify renewal ownership and the supported renewal path. Do not promise automatic or permanent retention. The current SDK API exposes expiry metadata but no renewal method; until a verified renewal mechanism is implemented, surface expiry and operational remediation honestly.
- [ ] Confirm deletion/forget behavior separately from blob expiry; do not claim a record is erased merely because its local metadata was revoked.

## Semantic-analysis safety

- [ ] Label both source content and recalled memory as untrusted data in the model request. (Separate structured fields, no tools, and current-content evidence validation are implemented; endpoint integration pending.)
- [ ] Send only bounded fields, with no arbitrary tools or production secrets. Keep memory in a distinct structured field, never as privileged instructions.
- [ ] Validate exact structured output, indexes, categories, rationale length, and consistency. Invalid output becomes inconclusive; it never promotes memory or returns a clean result.
- [ ] Preserve deterministic findings if semantic analysis disagrees. The model may add context or mark uncertainty, but policy remains deterministic and server-owned.

## First complete vertical slice: restart-and-recall

- [ ] A protected external agent submits direct content and provenance using the TypeScript SDK/API. (HTTP API implemented and tested; SDK remains pending.)
- [ ] SIEVE detects a fixture attack and returns a structured, evidence-backed assessment with a quarantine/review decision.
- [ ] The SDK example enforces that decision before the content enters agent context.
- [ ] SIEVE writes a minimized candidate record to the real configured Walrus Memory integration; PostgreSQL records its operation and blob references.
- [ ] An authorized reviewer validates and promotes that candidate to active in the correct scope.
- [ ] Restart the API. Submit a related, previously unseen paraphrase. Initial detection runs, then validated memory is recalled and independently scope/status checked before final policy.
- [ ] The response explains the recalled memory's supporting contribution while retaining fresh evidence as the basis for the finding.
- [ ] Submit benign lookalikes and show that memory similarity alone does not cause quarantine.
- [ ] Run the same held-out fixtures with memory off and on. Report dataset version, prior exposure, precision, recall, false positives/negatives, per-category results, memory hits, and limitations. Claim improvement only when measured results support it.

## Dependency-aware delivery order

1. Baseline the `core` branch, dependencies, database, migrations, and current API behavior; preserve the frontend worker's files.
2. Record architecture and checklist updates; agree the versioned inspection contract with the frontend owner.
3. Extend PostgreSQL for workspaces, protected agents, scoped credentials, policies, general inspections, memory lifecycle/review, memory operations, and audit events through additive migrations. (Migration 0002 added; storage methods and integration verification pending.)
4. Add tested direct-content inspection and policy behavior independent of Tatum. (HTTP vertical slice implemented; SDK integration pending.)
5. Add validated memory recall before final assessment, then controlled candidate write/review/promotion and real Walrus restart verification.
6. Add TypeScript SDK and the enforcement example; integrate UI only after locating and coordinating its source.
7. Measure memory-on/off behavior and false-positive controls; add Tatum/Sui as an adapter to the same inspection pipeline.

At each step, add tests at the public inspection, memory-lifecycle, storage, or SDK seams before implementation. Run targeted tests, typechecks, build, and migrations applicable to that step. Report real-provider checks separately from fixtures.
