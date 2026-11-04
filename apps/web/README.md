# SIEVE web

The authenticated, read-only browser client for SIEVE's inspection API.

## Local development

Run the API on port `3001`, then start the web client from the repository root:

```sh
pnpm --filter @sieve/web dev
```

Vite proxies `/api` requests to `http://localhost:3001`. Set `VITE_API_BASE_URL` when the API is hosted on a different origin. The API must allow browser requests from that origin in deployed environments.

The current API accepts a bearer token rather than providing a browser sign-in redirect. Enter a valid access token on the connect screen. It is kept in this tab's `sessionStorage` and removed when you disconnect.

## Available views

- Overview and paginated inspection history
- Sui object and transaction inspection
- Case status, evidence provenance, findings, chain facts, quarantined text, and retry
- Read-only threat memory history and normalized record detail
- Baseline and held-out variant detector evaluations with persisted run history and category metrics
- Integration health and configuration status

Threat memory creation remains unavailable until the controlled write workflow is implemented. Evaluation results come from small, manually authored fixture sets; the held-out variants are separate from baseline examples but do not provide independent external validation or a safety certification. The client does not substitute sample records for live results.
