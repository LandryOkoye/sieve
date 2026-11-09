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
Tatum and Walrus are reported as `unverified` until their connection checks are
wired in; configured values are never reported as a successful connection by
presence alone.

## Operational metrics

When `METRICS_BEARER_TOKEN` is configured, `GET /metrics` returns Prometheus text metrics for process uptime and memory, background-worker activity, and completed HTTP request counts by bounded route, method, and status. Scrape it with `Authorization: Bearer <token>`. The endpoint returns `404` when metrics are disabled and never emits request query strings, identifiers, or credentials. Keep the token in the deployment's secret store.
