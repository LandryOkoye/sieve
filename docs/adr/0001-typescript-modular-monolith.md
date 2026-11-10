# ADR 0001: Keep the SIEVE backend as a TypeScript modular monolith

- **Status:** Accepted
- **Date:** 2026-11-09
- **Decision owner:** SIEVE project owner

## Context

SIEVE is general AI-agent defense infrastructure. The existing backend is a TypeScript/Node workspace with a PostgreSQL adapter, Sui/Tatum evidence adapter, deterministic and optional semantic detection, Walrus Memory integration, and evaluation code. The current runtime is still centered on user-owned Sui inspection cases; it does not yet provide the approved direct-content agent integration or validated-memory recall loop.

The project documents have contained conflicting backend directions. The project owner approved continuing in TypeScript and explicitly rejected a Java/Spring Boot rewrite and unnecessary independently deployed services.

## Decision

Keep the core API, authentication, authorization, inspection orchestration, evidence normalization, detection, policy, PostgreSQL persistence, and audit history in the existing TypeScript/Node application.

Use a modular monolith. Keep Walrus Memory behind a focused TypeScript adapter in the same deployment by default. Add another deployment unit only when an identified reliability, security, or scaling requirement justifies it.

Direct-content inspection is a source-independent path. It must work when Tatum is absent or unavailable. Sui through Tatum is one evidence adapter and remains a secondary investigation surface.

PostgreSQL is the source of truth for SIEVE identity, agents, credentials, policies, inspection decisions, memory lifecycle state, provider operations, and audit records. Walrus Memory stores only minimized, SIEVE-authored threat-pattern records intended for persistent semantic recall.

## Consequences

- Reuse and extend the existing TypeScript packages instead of migrating them to another language.
- Keep provider interfaces narrow and test them with contract fixtures; do not add abstractions without a second real implementation or test substitute.
- Keep work on the `core` branch; coordinate REST contract changes with the separate `frontend` branch.
- Do not describe the current Sui case workflow as the complete SIEVE product.
- This decision supersedes any older Java/Spring Boot direction in project handoff notes. The product and technical requirements remain authoritative for security, lifecycle, and acceptance behavior.
