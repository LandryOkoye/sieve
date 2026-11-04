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
- Baseline and held-out variant detector evaluations with persisted run history, category metrics, and acceptance-target status
- Integration health and configuration status

Threat memory creation remains unavailable until the controlled write workflow is implemented. Evaluation targets are at least 97% overall recall, at least 85% recall per category, and at most 10% false positives. Fixture choices distinguish baseline regression, development, variant challenge, and frozen validation runs. The validation examples are stored in the repository and are not independent external validation or a safety certification. The client does not substitute sample records for live results.
- Integration health and configuration status

Threat memory and evaluation views remain unavailable until their API workflows are implemented. The client does not substitute sample records for live results.
