# SIEVE API

The API listens on port `3001` by default. Set `API_PORT` to change it.

## Integration configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection URL |
| `TATUM_API_KEY` | Server-side key for Tatum Sui gRPC |
| `TATUM_NETWORK` | `testnet` (default) or `mainnet` |
| `MEMWAL_ACCOUNT_ID` | Walrus Memory account used by SIEVE |
| `MEMWAL_PRIVATE_KEY` | Delegate key for the SIEVE API; keep it server-side |
| `MEMWAL_SERVER_URL` | Optional Walrus Memory relayer URL; defaults to the relayer for `TATUM_NETWORK` |
| `MEMWAL_NAMESPACE` | Optional namespace for SIEVE threat memories; defaults to `sieve-threat-memory` |
| `AUTH_ISSUER` | OIDC issuer URL for API access tokens |
| `AUTH_AUDIENCE` | Expected audience claim for API access tokens |
| `AUTH_JWKS_URL` | HTTPS URL for the issuer's signing keys |
| `METRICS_BEARER_TOKEN` | Optional, at least 32-character token protecting the Prometheus `/metrics` endpoint |
| `OPENAI_API_KEY` | Optional server-side key for semantic classification of untrusted chain text |
| `OPENAI_MODEL` | Required with `OPENAI_API_KEY`; model ID supporting Responses API Structured Outputs |
| `GROQ_API_KEY` | Optional server-side Groq key for the semantic judge |
| `GROQ_MODEL` | Optional with `GROQ_API_KEY`; defaults to `openai/gpt-oss-20b`, a Groq strict Structured Outputs model |
| `NVIDIA_API_KEY` | Optional server-side NVIDIA API key for the semantic judge |
| `NVIDIA_MODEL` | Required with `NVIDIA_API_KEY`; choose a model that supports JSON Schema output |
| `SEMANTIC_JUDGE_PROVIDER` | Optional `openai`, `groq`, or `nvidia` selector when multiple providers are configured |

All three `AUTH_*` values must be configured together. `GET /api/v1/me` requires
a valid bearer token and a configured PostgreSQL database, then returns the
stable SIEVE user ID associated with the token's verified issuer and subject.

### Google Sign-In

The web client uses Google Identity Services to obtain a Google ID token. The
browser sends that signed token to the API as a bearer token. The API verifies
the token with Google's rotating public keys before resolving the user's SIEVE
identity. The database key is the verified `(issuer, subject)` pair; do not use
email as the identity key.

Configure the API with these values in the project root `.env` file:

```env
AUTH_ISSUER=https://accounts.google.com
AUTH_AUDIENCE=your-web-client-id.apps.googleusercontent.com
AUTH_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
```

`AUTH_AUDIENCE` must exactly match the OAuth Web Client ID that Google issues
the ID token for. `AUTH_JWKS_URL` is Google's public signing-key endpoint; it is
not a credential. These values are configuration, not secrets. Do not put a
Google client secret in the API environment for this Sign in with Google flow.

In Google Cloud Console, create an OAuth client with type **Web application**.
Authorize `http://localhost:5173` as a JavaScript origin for local development
and add the exact staging origin before deploying the frontend. The frontend
uses the public client ID as `VITE_GOOGLE_CLIENT_ID` in
`apps/web/.env.local`; the same ID is set as `AUTH_AUDIENCE` on this API.

Docker Compose reads API settings from the project root `.env` automatically.
For direct API development, export those variables into the shell before
starting the API. The Vite development server reads frontend settings from
`apps/web/.env.local`; restart both processes after changing configuration.

If sign-in returns `unauthenticated`, check that the frontend client ID equals
`AUTH_AUDIENCE`, the token issuer equals `AUTH_ISSUER`, and the JWKS URL is
reachable from the API. If the API returns
`authentication_not_configured`, set all three `AUTH_*` values together.

The API verifies tokens locally and does not call Google's user-info endpoint
for each request. The browser stores only the ID token for the current tab; it
does not keep a refresh token. A Workspace-domain restriction is not enabled by
default; enforce a verified `hd` claim in the API if access must be limited to
accounts from a particular organization.

API responses include no-sniff, no-frame, no-referrer, no-store, and restrictive
content-security headers. Terminate HTTPS at a trusted deployment boundary;
the API does not set HSTS because TLS termination belongs to that boundary.

The liveness route reports whether the process is running. Readiness applies
the SQL migrations and checks PostgreSQL when `DATABASE_URL` is configured.
When configured, Tatum and Walrus readiness performs live provider health
checks; credentials being present alone never reports a successful connection.

The API writes a normalized threat-memory record only when the write policy
accepts a strong detector signal backed by complete Tatum evidence. The original
chain text is not sent to Walrus. The record is saved to PostgreSQL before the
SDK call, and `rememberAndWait` uses content deduplication so retries do not
create duplicate memories. Failed writes remain visible in the user's memory
history and are retried when the case is retried. The SDK validates recalled
records and marks them untrusted; the API does not yet use recalls in case
assessments.

## Local container deployment

Run `docker compose up --build -d` from the repository root to start PostgreSQL
and the API. The API is bound to `127.0.0.1:3001` by default, waits for the
database health check, and has a liveness check. Set optional provider and OIDC
variables in the shell or an untracked root `.env` file before starting the
stack. Do not commit that file. The local database password default is for
development only; use a managed secret and database service for shared or
production deployments. The API container runs as the unprivileged Node user
with a read-only root filesystem and dropped Linux capabilities.

Use `docker compose logs -f api` to inspect startup output and
`docker compose down` to stop the services. PostgreSQL data remains in the
`sieve-postgres` volume. See the repository backup and restore scripts before
replacing or deleting that volume. This Compose setup is a local deployment
baseline; production still needs TLS termination, configured authentication,
managed backups, and a reviewed release and rollback procedure.

The 2026-11-05 local security review and remaining deployment requirements are recorded in [the review report](security-review-2026-11-05.md).

## Optional semantic judge

The deterministic detector works without an LLM. To enable the semantic judge,
configure a provider key and model pair: `OPENAI_API_KEY` with `OPENAI_MODEL`,
`GROQ_API_KEY` with `GROQ_MODEL`, or `NVIDIA_API_KEY` with `NVIDIA_MODEL`.
When multiple providers are configured, select one with
`SEMANTIC_JUDGE_PROVIDER`. The API sends bounded, extracted chain text with
strict JSON Schema output and no tools. OpenAI requests use the Responses API
and disable response storage; Groq requests use its Responses API and omit the
unsupported `store` parameter; NVIDIA requests use its Chat Completions API and
`response_format` JSON Schema. NVIDIA currently documents JSON Schema output
for models such as `nvidia/nemotron-3.5-super-vl-120b-a12b`. Groq currently
documents strict Structured Outputs for models such as `openai/gpt-oss-20b` and
`openai/gpt-oss-120b`. It runs only when deterministic rules
find no signal. The model can add suspicious findings but cannot remove rule
findings, write threat memory, or modify policy.
The text is explicitly classified as untrusted data. A timeout, refusal,
malformed response, or unavailable provider produces uncertainty when no rule
matched, never a clean verdict. Do not configure the integration if chain text
must not be sent to an external classifier. Evaluation runs record the model ID
but never the API key. A queued run uses the provider and model snapshot recorded when it was
created; if that model is no longer configured when processing begins, the run
fails with `evaluation_config_unavailable` rather than silently switching to a
different detector configuration. Assessment revisions record the rules-only
version or the configured rules-plus-model version for provenance.

Run the frozen held-out validation from the API workspace with
`pnpm --filter @sieve/api evaluate:validation`. Set
`SIEVE_EVALUATION_REPEATS` to an integer from 1 to 10 to measure run-to-run
variation; it defaults to one run. The command uses the configured semantic
judge, prints metrics, provider/model metadata, and index-only diagnostics for
overall or category misclassifications. It never prints credentials or fixture text. Each run
makes a live provider request and may incur usage charges.
Set `SIEVE_EVALUATION_FIXTURE_SET=sieve-dev-v3` to run the diagnostic-guided
development set instead; only the default validation set may be used for
threshold acceptance reporting.

## Operational metrics

When `METRICS_BEARER_TOKEN` is configured, `GET /metrics` returns Prometheus text metrics for process uptime and memory, background-worker activity, and completed HTTP request counts by bounded route, method, and status. Scrape it with `Authorization: Bearer <token>`. The endpoint returns `404` when metrics are disabled and never emits request query strings, identifiers, or credentials. Keep the token in the deployment's secret store.
