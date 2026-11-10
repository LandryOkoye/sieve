CREATE TABLE workspaces (
  id text PRIMARY KEY,
  owner_user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
  workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'reviewer', 'member')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX workspace_members_user ON workspace_members (user_id, workspace_id);

CREATE TABLE protected_agents (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  policy jsonb NOT NULL DEFAULT '{"default":"review","includeGlobalMemory":false}'::jsonb,
  policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id)
);
CREATE INDEX protected_agents_workspace ON protected_agents (workspace_id, created_at DESC);

CREATE TABLE agent_credentials (
  id text PRIMARY KEY,
  workspace_id text NOT NULL,
  agent_id text NOT NULL,
  token_hash char(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  token_prefix text NOT NULL CHECK (length(token_prefix) BETWEEN 8 AND 32),
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES protected_agents(workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX agent_credentials_agent ON agent_credentials (agent_id, created_at DESC);

CREATE TABLE direct_inspections (
  id text PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200),
  content_sha256 char(64) NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
  content_bytes integer NOT NULL CHECK (content_bytes BETWEEN 0 AND 65536),
  source_type text NOT NULL CHECK (length(source_type) BETWEEN 1 AND 80),
  source_ref_hash char(64),
  outcome text NOT NULL CHECK (outcome IN ('signals_detected', 'no_signals_detected', 'uncertain')),
  action text NOT NULL CHECK (action IN ('allow', 'review', 'block')),
  findings jsonb NOT NULL,
  memory_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  detector_version text NOT NULL,
  policy_version integer NOT NULL CHECK (policy_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES protected_agents(workspace_id, id) ON DELETE CASCADE,
  UNIQUE (agent_id, request_id)
);
CREATE INDEX direct_inspections_agent_created ON direct_inspections (agent_id, created_at DESC, id DESC);
CREATE INDEX direct_inspections_expiry ON direct_inspections (expires_at);

CREATE TABLE threat_memories (
  id text PRIMARY KEY,
  scope text NOT NULL CHECK (scope IN ('agent', 'workspace', 'global')),
  workspace_id text REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_id text,
  category text NOT NULL,
  technique_id text NOT NULL,
  safe_fingerprint char(64) NOT NULL CHECK (safe_fingerprint ~ '^[a-f0-9]{64}$'),
  minimized_record jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('candidate', 'validated', 'active', 'superseded', 'revoked', 'rejected', 'false_positive')),
  created_by text NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
  walrus_blob_id text,
  walrus_job_id text,
  walrus_status text NOT NULL DEFAULT 'pending' CHECK (walrus_status IN ('pending', 'stored', 'failed', 'expired')),
  walrus_end_epoch bigint,
  walrus_expires_at timestamptz,
  last_reconciled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (scope = 'global' AND workspace_id IS NULL AND agent_id IS NULL) OR
    (scope = 'workspace' AND workspace_id IS NOT NULL AND agent_id IS NULL) OR
    (scope = 'agent' AND workspace_id IS NOT NULL AND agent_id IS NOT NULL)
  ),
  FOREIGN KEY (workspace_id, agent_id) REFERENCES protected_agents(workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX threat_memories_scope_status ON threat_memories (scope, workspace_id, agent_id, status, updated_at DESC);
CREATE INDEX threat_memories_walrus_expiry ON threat_memories (walrus_expires_at) WHERE status = 'active';

CREATE TABLE memory_review_events (
  id text PRIMARY KEY,
  memory_id text NOT NULL REFERENCES threat_memories(id) ON DELETE CASCADE,
  reviewer_user_id text NOT NULL REFERENCES app_users(id) ON DELETE RESTRICT,
  action text NOT NULL CHECK (action IN ('validate', 'promote', 'reject', 'mark_false_positive', 'revoke')),
  rationale text NOT NULL CHECK (length(trim(rationale)) BETWEEN 12 AND 500),
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX memory_review_events_memory ON memory_review_events (memory_id, created_at DESC);

CREATE TABLE agent_audit_events (
  id text PRIMARY KEY,
  workspace_id text REFERENCES workspaces(id) ON DELETE SET NULL,
  agent_id text REFERENCES protected_agents(id) ON DELETE SET NULL,
  inspection_id text REFERENCES direct_inspections(id) ON DELETE SET NULL,
  actor_user_id text REFERENCES app_users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_audit_events_created ON agent_audit_events (workspace_id, created_at DESC);
