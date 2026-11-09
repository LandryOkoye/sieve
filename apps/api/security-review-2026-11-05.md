# Local API security review

**Date:** 2026-11-05
**Scope:** Static review of the current local implementation for M8 readiness.
**Result:** No actionable code finding identified in the reviewed paths.

## Areas reviewed

- OIDC issuer and audience validation, JWKS URL validation, and bearer-token handling.
- Route authentication and per-user scoping for cases, evaluations, and threat-memory records.
- Parameterized database queries, bounded pagination, request-size limits, and identifier validation.
- Evidence extraction limits and the treatment of chain text and recalled memory as untrusted data.
- Threat-memory write provenance checks and strict schema validation on recall.
- Semantic-judge boundaries: bounded text, structured output, no tools, and failure-to-uncertainty behavior.
- Container defaults: unprivileged Node user, read-only root filesystem, dropped capabilities, and loopback port binding.
- The most recent validation-v3 commit against repository commit rules and evaluation requirements; the focused standards/spec review found no actionable issues.

## Deployment work still required

This was a source review of the local application, not a penetration test, dependency audit, or certification. Before production, the deployment must still:

No live attack traffic or probing against external services was performed.

- Terminate HTTPS at a trusted boundary and configure a production identity provider.
- Store provider and database credentials in a managed secret store.
- Define data retention and deletion behavior for evidence and identity-linked records.
- Store backups encrypted with access controls and a retention policy.
- Rehearse restoration with the deployment's PostgreSQL version and validate application reads before cutover.
- Review release compatibility with forward-only migrations and document the deployment-specific rollback decision path.

No changes were made to production configuration or external services during this review. These deployment requirements remain open until the target environment is known and configured.
