BEGIN;

CREATE TABLE app_users (
  id text PRIMARY KEY,
  identity_issuer text NOT NULL,
  identity_subject text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (identity_issuer, identity_subject)
);

CREATE TABLE inspection_cases (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  network text NOT NULL CHECK (network IN ('mainnet', 'testnet')),
  target_kind text NOT NULL CHECK (target_kind IN ('transaction', 'object')),
  transaction_digest text,
  object_id text,
  status text NOT NULL CHECK (status IN ('queued', 'fetching_evidence', 'assessing', 'completed', 'failed')),
  evidence jsonb,
  failure_code text,
  idempotency_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (target_kind = 'transaction' AND transaction_digest IS NOT NULL AND object_id IS NULL) OR
    (target_kind = 'object' AND object_id IS NOT NULL AND transaction_digest IS NULL)
  )
);

CREATE UNIQUE INDEX inspection_cases_user_idempotency
  ON inspection_cases (user_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX inspection_cases_user_created
  ON inspection_cases (user_id, created_at DESC, id DESC);

CREATE TABLE assessment_revisions (
  id text PRIMARY KEY,
  case_id text NOT NULL REFERENCES inspection_cases(id) ON DELETE CASCADE,
  revision integer NOT NULL CHECK (revision > 0),
  detector_version text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('signals_detected', 'no_signals_detected', 'uncertain')),
  result jsonb NOT NULL,
  safe_summary text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, revision)
);

CREATE TABLE threat_memory_writes (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  case_id text NOT NULL REFERENCES inspection_cases(id) ON DELETE CASCADE,
  pattern text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'accepted', 'uploaded', 'completed', 'failed')),
  normalized_record jsonb NOT NULL,
  walrus_job_id text UNIQUE,
  blob_id text,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, pattern)
);
CREATE INDEX threat_memory_writes_user_created
  ON threat_memory_writes (user_id, created_at DESC, id DESC);

CREATE TABLE evaluation_runs (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  fixture_set_version text NOT NULL,
  detector_config jsonb NOT NULL,
  metrics jsonb,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX evaluation_runs_user_created
  ON evaluation_runs (user_id, created_at DESC, id DESC);

CREATE TABLE audit_events (
  id text PRIMARY KEY,
  user_id text REFERENCES app_users(id) ON DELETE SET NULL,
  case_id text REFERENCES inspection_cases(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_created
  ON audit_events (user_id, created_at DESC, id DESC);

COMMIT;
