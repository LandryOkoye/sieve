# SIEVE web

The authenticated browser console for SIEVE's agent-defense API. Direct-content inspection is the primary workflow; Sui evidence is an optional provider integration.

## Local development

Run the API on port `3001`, then start the web client from the repository root:

```sh
pnpm --filter @sieve/web dev
```

Vite proxies `/api` requests to `http://localhost:3001`. Set `VITE_API_BASE_URL` when the API is hosted on a different origin. The API must allow browser requests from that origin in deployed environments.

The connect screen uses Google's official Sign in with Google button. It sends Google's ID token to the API as a bearer token; the API validates its signature, issuer, expiry, and audience before creating the SIEVE user session. The ID token stays in this tab's `sessionStorage` and is removed when you disconnect.

After sign-in, workspace owners can provision a protected agent. Its `sieve_live_` credential is returned once and held only in the current page state. Agents submit content to `/api/v1/agent/inspect`; the UI shows the evidence-backed decision and keeps review/block results out of trusted context. The API persists a content hash and assessment metadata, not the raw content.

The browser API helpers expose this flow:

- `api.createProtectedAgent(idToken, name)` provisions an agent and returns its one-time credential.
- `api.inspectAgentContent(agentCredential, content, sourceType, sourceRef?)` sends direct content for inspection.
- Each inspection gets a fresh `Idempotency-Key` so network retries cannot create duplicate records.
- `decision.action` is one of `allow`, `review`, or `block` and must be enforced by the caller.
- A `review` or `block` result must stay out of trusted agent context.
- Findings include evidence references; recalled memory is reported as supporting context.
- Strong findings may create a `candidate` memory; candidates are not trusted or retrievable until reviewed.
- The browser must not put agent credentials into URLs, logs, analytics, or persistent browser storage.

The **Protect content** screen provisions a key or accepts an existing agent key, submits direct content, and presents the server-owned decision with current-content findings. It shows memory hits as context and new observations as pending candidates, never as trusted memory.

When a strong finding creates a candidate, a workspace reviewer can enter a rationale and validate it from the assessment result. Validation does not make the record retrievable: the reviewer must separately promote it. Promotion is enabled only after the candidate write is confirmed in Walrus, and the API verifies a fresh active blob and expiry. The API checks reviewer authorization and memory scope for every action; the browser is not the trust boundary. Rejected candidates remain non-retrievable.

#### Candidate review states

- **Candidate:** detector evidence has produced a minimized observation; it is excluded from recall.
- **Validate:** an authorized workspace reviewer records a rationale and confirms the evidence supports the pattern.
- **Validated:** the review is recorded, but the record is still excluded from recall.
- **Promote active:** the reviewer makes a separate decision; the API writes a fresh Walrus record and verifies its expiry.
- **Active:** PostgreSQL and the exact active Walrus blob reference authorize scoped recall.
- **Reject:** the observation remains unavailable to inspection decisions.
- The UI always shows Walrus write status alongside lifecycle status.
- Promotion stays disabled when storage is pending or failed.
- The reviewer rationale is required for each transition.
- A successful action updates the candidate status returned by the API.
- Failed or unauthorized transitions stay visible as errors and do not change the local status.
- Recalled memory is displayed as context; the current inspection remains the evidence source.
- Memory records from the legacy Sui case workflow are shown on a separate page and are not presented as validated agent memory.
- Agent credentials remain in page memory and are not saved across reloads.
- Review requests include only the record ID, action, and reviewer rationale.

The signed-in dashboard opens on the agent-defense workflow and shows direct-content assessments from the current browser session. Sui case history is available separately as the first optional chain-evidence integration.

## Product boundaries

- The **Dashboard** and **Protect content** views use the general agent-defense API; neither requires a blockchain provider.
- The API decides whether to allow, review, or block. Integrating agents must enforce that result before adding inspected material to trusted context.
- Memory hits are supporting evidence only. The current inspection and server policy remain authoritative.
- A detector-created candidate is not a trusted memory. Only an authorized reviewer can validate and then promote it.
- Global, workspace, and agent memory scopes are enforced by the API; the browser does not grant access by selecting a scope.
- The **Sui evidence** views fetch public Sui objects or transactions through the optional chain connector.
- The **Sui memory activity** view describes legacy case-workflow writes. It is not the registry used for agent-memory recall.
- Dashboard assessment history is held in page state and lasts only for the current browser session.
- The web client does not expose API secrets or persist protected-agent credentials. Keep agent credentials in the integrating agent's secret store.
- Optional semantic analysis receives untrusted content and returns structured findings; it cannot change memory lifecycle state or perform actions.
- Do not submit system prompts, credentials, private conversations, or sensitive context unless the integration has explicit authorization to inspect them.
- The console reports the server's assessment and policy decision; it does not claim that a no-signal result guarantees safe content.
- Learning claims require the evaluation workflow to compare persistent-memory results against unseen variations and false-positive targets.

Create an OAuth client of type **Web application** in Google Cloud. Add `http://localhost:5173` as an authorized JavaScript origin. Copy `apps/web/.env.example` to `apps/web/.env.local` and set `VITE_GOOGLE_CLIENT_ID` to the client ID. No client secret is used by the browser or API for this ID-token flow.

Set these API values in the project root `.env` file. Docker Compose reads this file automatically; when running the API directly, export its variables into the shell before starting it:

```env
AUTH_ISSUER=https://accounts.google.com
AUTH_AUDIENCE=your-web-client-id.apps.googleusercontent.com
AUTH_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
```

Use the same OAuth client ID for `VITE_GOOGLE_CLIENT_ID` and `AUTH_AUDIENCE`. The API validates Google ID-token signatures using Google's public signing keys and scopes records by the verified issuer and subject. Restart Vite and the API after configuring these values. Add the staging site's origin as an authorized JavaScript origin before staging sign-in.

## Available views

- Agent-defense dashboard with service state and current-session assessment summaries
- Protected-agent provisioning, direct-content inspection, policy decision, evidence spans, and candidate review actions
- Sui object and transaction inspection as an optional evidence integration
- Sui case status, provenance, findings, chain facts, quarantined text, and retry
- Legacy Sui memory-write status, clearly separated from validated agent threat memory
- Baseline, development, and frozen validation detector evaluations with persisted run history, category metrics, and acceptance-target status
- Integration health and configuration status

The agent screen can validate and promote a candidate returned by the current inspection. The API remains the authority for reviewer permissions, scope checks, and Walrus expiry. The UI does not yet list lifecycle candidates after leaving their assessment; it never treats the legacy Sui memory-write page as the reviewed agent-memory registry. Evaluation targets are at least 97% overall recall, at least 85% recall per category, and at most 10% false positives. Fixture choices distinguish baseline regression, development, and frozen validation runs. When the configured semantic judge is enabled, fixture text is sent to that provider; run details identify the model used. The validation examples are stored in the repository and are not independent external validation or a safety certification. The client does not substitute sample records for live results.
