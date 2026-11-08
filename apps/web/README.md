# SIEVE web

The authenticated, read-only browser client for SIEVE's inspection API.

## Local development

Run the API on port `3001`, then start the web client from the repository root:

```sh
pnpm --filter @sieve/web dev
```

Vite proxies `/api` requests to `http://localhost:3001`. Set `VITE_API_BASE_URL` when the API is hosted on a different origin. The API must allow browser requests from that origin in deployed environments.

The connect screen supports OIDC authorization-code sign-in with PKCE. Configure a public SPA client in your identity provider and allow `http://localhost:5173/` as a redirect URI. The app verifies the ID token signature, issuer, audience, and nonce before sending its access token to the API. Tokens stay in this tab's `sessionStorage` and are removed when you disconnect. Manual bearer-token entry is available only in Vite development mode.

Copy `apps/web/.env.example` to `apps/web/.env.local` and set `VITE_OIDC_ISSUER` and `VITE_OIDC_CLIENT_ID`. The issuer must exactly match the API's `AUTH_ISSUER`. Configure `AUTH_AUDIENCE` on the API to match the access token; set `VITE_OIDC_AUDIENCE` when your provider requires an audience parameter in the authorization request. No client secret belongs in the browser app. The identity provider must allow discovery, JWKS, and token-exchange requests from the browser origin.

## Available views

- Overview and paginated inspection history
- Sui object and transaction inspection
- Case status, evidence provenance, findings, chain facts, quarantined text, and retry
- Read-only threat memory history and normalized record detail
- Baseline, development, and frozen validation detector evaluations with persisted run history, category metrics, and acceptance-target status
- Integration health and configuration status

Threat memory creation remains unavailable until the controlled write workflow is implemented. Evaluation targets are at least 97% overall recall, at least 85% recall per category, and at most 10% false positives. Fixture choices distinguish baseline regression, development, and frozen validation runs. When the optional OpenAI judge is configured, evaluation fixture text is sent to that provider; run details identify the model used. The validation examples are stored in the repository and are not independent external validation or a safety certification. The client does not substitute sample records for live results.
