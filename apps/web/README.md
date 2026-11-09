# SIEVE web

The authenticated, read-only browser client for SIEVE's inspection API.

## Local development

Run the API on port `3001`, then start the web client from the repository root:

```sh
pnpm --filter @sieve/web dev
```

Vite proxies `/api` requests to `http://localhost:3001`. Set `VITE_API_BASE_URL` when the API is hosted on a different origin. The API must allow browser requests from that origin in deployed environments.

The connect screen uses Google's official Sign in with Google button. It sends Google's ID token to the API as a bearer token; the API validates its signature, issuer, expiry, and audience before creating the SIEVE user session. The ID token stays in this tab's `sessionStorage` and is removed when you disconnect.

Create an OAuth client of type **Web application** in Google Cloud. Add `http://localhost:5173` as an authorized JavaScript origin. Copy `apps/web/.env.example` to `apps/web/.env.local` and set `VITE_GOOGLE_CLIENT_ID` to the client ID. No client secret is used by the browser or API for this ID-token flow.

Set these API values in the project root `.env` file. Docker Compose reads this file automatically; when running the API directly, export its variables into the shell before starting it:

```env
AUTH_ISSUER=https://accounts.google.com
AUTH_AUDIENCE=your-web-client-id.apps.googleusercontent.com
AUTH_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
```

Use the same OAuth client ID for `VITE_GOOGLE_CLIENT_ID` and `AUTH_AUDIENCE`. The API validates Google ID-token signatures using Google's public signing keys and scopes records by the verified issuer and subject. Restart Vite and the API after configuring these values. Add the staging site's origin as an authorized JavaScript origin before staging sign-in.

## Available views

- Overview and paginated inspection history
- Sui object and transaction inspection
- Case status, evidence provenance, findings, chain facts, quarantined text, and retry
- Read-only threat memory history and normalized record detail
- Baseline, development, and frozen validation detector evaluations with persisted run history, category metrics, and acceptance-target status
- Integration health and configuration status

Threat memory creation remains unavailable until the controlled write workflow is implemented. Evaluation targets are at least 97% overall recall, at least 85% recall per category, and at most 10% false positives. Fixture choices distinguish baseline regression, development, and frozen validation runs. When the optional OpenAI judge is configured, evaluation fixture text is sent to that provider; run details identify the model used. The validation examples are stored in the repository and are not independent external validation or a safety certification. The client does not substitute sample records for live results.
