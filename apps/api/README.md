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
| `MEMWAL_SERVER_URL` | Optional Walrus Memory relayer URL |
| `MEMWAL_NAMESPACE` | Optional namespace for SIEVE threat memories |
| `AUTH_ISSUER` | OIDC issuer URL for API access tokens |
| `AUTH_AUDIENCE` | Expected audience claim for API access tokens |
| `AUTH_JWKS_URL` | HTTPS URL for the issuer's signing keys |
| `METRICS_BEARER_TOKEN` | Optional, at least 32-character token protecting the Prometheus `/metrics` endpoint |
| `OPENAI_API_KEY` | Optional server-side key for semantic classification of untrusted chain text |
| `OPENAI_MODEL` | Required with `OPENAI_API_KEY`; model ID supporting Responses API Structured Outputs |

All three `AUTH_*` values must be configured together. `GET /api/v1/me` requires
a valid bearer token and a configured PostgreSQL database, then returns the
stable SIEVE user ID associated with the token's verified issuer and subject.

API responses include no-sniff, no-frame, no-referrer, no-store, and restrictive
content-security headers. Terminate HTTPS at a trusted deployment boundary;
the API does not set HSTS because TLS termination belongs to that boundary.

The liveness route reports whether the process is running. Readiness applies
the SQL migrations and checks PostgreSQL when `DATABASE_URL` is configured.
Tatum and Walrus are reported as `unverified` until their connection checks are
wired in; configured values are never reported as a successful connection by
presence alone.

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

## Optional semantic judge

The deterministic detector works without an LLM. To enable the semantic judge,
configure both `OPENAI_API_KEY` and `OPENAI_MODEL`; the API sends bounded,
extracted chain text to the OpenAI Responses API with strict JSON Schema output,
no tools, and response storage disabled. It runs only when deterministic rules
find no signal. The model can add suspicious findings but cannot remove rule
findings, write threat memory, or modify policy.
The text is explicitly classified as untrusted data. A timeout, refusal,
malformed response, or unavailable provider produces uncertainty when no rule
matched, never a clean verdict. Do not configure the integration if chain text
must not be sent to an external classifier. Evaluation runs record the model ID
but never the API key. A queued run uses the model snapshot recorded when it was
created; if that model is no longer configured when processing begins, the run
fails with `evaluation_config_unavailable` rather than silently switching to a
different detector configuration. Assessment revisions record the rules-only
version or the configured rules-plus-model version for provenance.

## Operational metrics

When `METRICS_BEARER_TOKEN` is configured, `GET /metrics` returns Prometheus text metrics for process uptime and memory, background-worker activity, and completed HTTP request counts by bounded route, method, and status. Scrape it with `Authorization: Bearer <token>`. The endpoint returns `404` when metrics are disabled and never emits request query strings, identifiers, or credentials. Keep the token in the deployment's secret store.
