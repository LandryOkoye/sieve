import { readdir, readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import type { DetectorVerdict, EvaluationDetectorConfig, EvaluationMetrics, EvaluationRun, EvidenceBundle, InspectionCase, LookupTarget, SuiNetwork, ThreatMemoryWrite } from "@sieve/contracts";
import { applyEvaluationThresholds } from "@sieve/evaluation";
import type { ThreatMemoryRecord } from "@sieve/threat-memory/policy";

const migrationsDirectory = new URL("../../../db/migrations/", import.meta.url);

export class Database {
  private readonly pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 10,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
    });
    this.pool.on("error", () => {
      process.stderr.write("An idle PostgreSQL connection failed.\n");
    });
  }

  async checkConnection(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async resolveUserId(issuer: string, subject: string): Promise<string> {
    const result = await this.pool.query<{ id: string }>(
      `INSERT INTO app_users (id, identity_issuer, identity_subject)
       VALUES ($1, $2, $3)
       ON CONFLICT (identity_issuer, identity_subject)
       DO UPDATE SET identity_subject = EXCLUDED.identity_subject
       RETURNING id`,
      [randomUUID(), issuer, subject],
    );
    const user = result.rows[0];
    if (!user) throw new Error("Could not resolve application user");
    return user.id;
  }

  async createCase(userId: string, network: SuiNetwork, target: LookupTarget, idempotencyKey: string | undefined): Promise<{ inspectionCase: InspectionCase; created: boolean }> {
    const id = randomUUID();
    const result = await this.pool.query<{ id: string }>(
      `INSERT INTO inspection_cases (id, user_id, network, target_kind, transaction_digest, object_id, status, idempotency_key)
       VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7)
       ON CONFLICT (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
       RETURNING id`,
      [id, userId, network, target.kind, target.kind === "transaction" ? target.digest : null, target.kind === "object" ? target.objectId : null, idempotencyKey ?? null],
    );
    const created = result.rowCount === 1;
    const caseId = result.rows[0]?.id ?? (await this.pool.query<{ id: string }>(
      "SELECT id FROM inspection_cases WHERE user_id = $1 AND idempotency_key = $2",
      [userId, idempotencyKey],
    )).rows[0]?.id;
    if (!caseId) throw new Error("Could not create or retrieve inspection case");
    const inspectionCase = await this.getCase(userId, caseId);
    if (!inspectionCase) throw new Error("Could not load inspection case");
    return { inspectionCase, created };
  }

  async updateCaseStatus(userId: string, caseId: string, status: InspectionCase["status"], evidence?: EvidenceBundle, failureCode?: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE inspection_cases SET status = $3, evidence = COALESCE($4::jsonb, evidence), failure_code = $5, updated_at = now()
       WHERE id = $1 AND user_id = $2`,
      [caseId, userId, status, evidence ? JSON.stringify(evidence) : null, failureCode ?? null],
    );
    if (result.rowCount !== 1) throw new Error("Inspection case was not found");
  }

  async recoverInterruptedCases(): Promise<void> {
    await this.pool.query(
      `UPDATE inspection_cases SET status = 'queued', failure_code = NULL, updated_at = now()
       WHERE status IN ('fetching_evidence', 'assessing') AND updated_at < now() - interval '2 minutes'`,
    );
    await this.pool.query(
      `UPDATE evaluation_runs SET status = 'queued', failure_code = NULL
       WHERE status = 'running' AND created_at < now() - interval '2 minutes'`,
    );
  }

  async claimNextCase(): Promise<{ userId: string; inspectionCase: InspectionCase } | null> {
    const result = await this.pool.query<{ id: string; user_id: string }>(
      `WITH next_case AS (
         SELECT id FROM inspection_cases WHERE status = 'queued'
         ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1
       )
       UPDATE inspection_cases c SET status = 'fetching_evidence', failure_code = NULL, updated_at = now()
       FROM next_case WHERE c.id = next_case.id RETURNING c.id, c.user_id`,
    );
    const claimed = result.rows[0];
    if (!claimed) return null;
    const inspectionCase = await this.getCase(claimed.user_id, claimed.id);
    return inspectionCase ? { userId: claimed.user_id, inspectionCase } : null;
  }

  async retryCase(userId: string, caseId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE inspection_cases SET status = 'queued', failure_code = NULL, updated_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'failed'`,
      [caseId, userId],
    );
    return result.rowCount === 1;
  }

  async saveAssessment(userId: string, caseId: string, verdict: DetectorVerdict, detectorVersion: string): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const owned = await client.query("SELECT id FROM inspection_cases WHERE id = $1 AND user_id = $2 FOR UPDATE", [caseId, userId]);
      if (owned.rowCount !== 1) throw new Error("Inspection case was not found");
      const revision = await client.query<{ revision: number | null }>("SELECT max(revision) AS revision FROM assessment_revisions WHERE case_id = $1", [caseId]);
      await client.query(
        `INSERT INTO assessment_revisions (id, case_id, revision, detector_version, outcome, result)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [randomUUID(), caseId, (revision.rows[0]?.revision ?? 0) + 1, detectorVersion, verdict.outcome, JSON.stringify(verdict)],
      );
      await client.query("UPDATE inspection_cases SET status = 'completed', updated_at = now() WHERE id = $1", [caseId]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getCase(userId: string, caseId: string): Promise<InspectionCase | null> {
    const result = await this.pool.query<CaseRow>(caseSelect + " WHERE c.user_id = $1 AND c.id = $2", [userId, caseId]);
    return result.rows[0] ? toInspectionCase(result.rows[0]) : null;
  }

  async getThreatMemoryWrite(userId: string, memoryId: string): Promise<ThreatMemoryWrite | null> {
    const result = await this.pool.query<ThreatMemoryRow>(
      `${threatMemorySelect} WHERE user_id = $1 AND id = $2`,
      [userId, memoryId],
    );
    return result.rows[0] ? toThreatMemoryWrite(result.rows[0]) : null;
  }

  async createThreatMemoryWrite(userId: string, caseId: string, record: ThreatMemoryRecord): Promise<ThreatMemoryWrite> {
    await this.pool.query(
      `INSERT INTO threat_memory_writes (id, user_id, case_id, pattern, status, normalized_record)
       VALUES ($1, $2, $3, $4, 'pending', $5::jsonb)
       ON CONFLICT (case_id, pattern) DO NOTHING`,
      [randomUUID(), userId, caseId, record.pattern, JSON.stringify(record)],
    );
    let result = await this.pool.query<ThreatMemoryRow>(
      `${threatMemorySelect} WHERE user_id = $1 AND case_id = $2 AND pattern = $3`,
      [userId, caseId, record.pattern],
    );
    let row = result.rows[0];
    if (!row) throw new Error("Could not create or load threat memory write");
    if (row.status === "failed") {
      await this.pool.query(
        `UPDATE threat_memory_writes SET status = 'pending', failure_code = NULL, updated_at = now()
         WHERE id = $1 AND user_id = $2 AND status = 'failed'`,
        [row.id, userId],
      );
      result = await this.pool.query<ThreatMemoryRow>(
        `${threatMemorySelect} WHERE user_id = $1 AND id = $2`,
        [userId, row.id],
      );
      row = result.rows[0];
    }
    if (!row) throw new Error("Could not load threat memory write");
    return toThreatMemoryWrite(row);
  }

  async completeThreatMemoryWrite(userId: string, memoryId: string, jobId: string, blobId: string): Promise<void> {
    const result = await this.pool.query(
      `UPDATE threat_memory_writes SET status = 'completed', walrus_job_id = $3, blob_id = $4,
       failure_code = NULL, updated_at = now() WHERE id = $1 AND user_id = $2 AND status <> 'completed'`,
      [memoryId, userId, jobId, blobId],
    );
    if (result.rowCount !== 1) throw new Error("Threat memory write could not be completed");
  }

  async failThreatMemoryWrite(userId: string, memoryId: string, failureCode: string): Promise<void> {
    await this.pool.query(
      `UPDATE threat_memory_writes SET status = 'failed', failure_code = $3, updated_at = now()
       WHERE id = $1 AND user_id = $2 AND status <> 'completed'`,
      [memoryId, userId, failureCode],
    );
  }

  async listThreatMemoryWrites(userId: string, limit: number, cursor?: { createdAt: string; id: string }): Promise<{ memories: ThreatMemoryWrite[]; hasMore: boolean; lastCursor: { createdAt: string; id: string } | null }> {
    const values: unknown[] = [userId];
    let cursorClause = "";
    if (cursor) {
      values.push(cursor.createdAt, cursor.id);
      cursorClause = " AND (created_at, id) < ($2::timestamptz, $3::text)";
    }
    values.push(limit + 1);
    const result = await this.pool.query<ThreatMemoryRow>(
      `${threatMemorySelect} WHERE user_id = $1${cursorClause} ORDER BY created_at DESC, id DESC LIMIT $${values.length}`,
      values,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit);
    const last = rows.at(-1);
    return {
      memories: rows.map(toThreatMemoryWrite),
      hasMore,
      lastCursor: last ? { createdAt: last.cursor_created_at, id: last.id } : null,
    };
  }

  async createEvaluation(userId: string, fixtureSetVersion: string, detectorConfig: EvaluationDetectorConfig): Promise<EvaluationRun> {
    const result = await this.pool.query<EvaluationRow>(
      `INSERT INTO evaluation_runs (id, user_id, status, fixture_set_version, detector_config)
       VALUES ($1, $2, 'queued', $3, $4::jsonb)
       RETURNING id, status, fixture_set_version, detector_config, metrics, failure_code, created_at, completed_at`,
      [randomUUID(), userId, fixtureSetVersion, JSON.stringify(detectorConfig)],
    );
    const row = result.rows[0];
    if (!row) throw new Error("Could not create evaluation run");
    return toEvaluationRun(row);
  }

  async claimNextEvaluation(): Promise<{ userId: string; evaluation: EvaluationRun } | null> {
    const result = await this.pool.query<{ id: string; user_id: string }>(
      `WITH next_run AS (
         SELECT id FROM evaluation_runs WHERE status = 'queued'
         ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1
       )
       UPDATE evaluation_runs e SET status = 'running'
       FROM next_run WHERE e.id = next_run.id RETURNING e.id, e.user_id`,
    );
    const claimed = result.rows[0];
    if (!claimed) return null;
    const evaluation = await this.getEvaluation(claimed.user_id, claimed.id);
    return evaluation ? { userId: claimed.user_id, evaluation } : null;
  }

  async completeEvaluation(userId: string, evaluationId: string, metrics: EvaluationMetrics): Promise<void> {
    const result = await this.pool.query(
      `UPDATE evaluation_runs SET status = 'completed', metrics = $3::jsonb, failure_code = NULL, completed_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'running'`,
      [evaluationId, userId, JSON.stringify(metrics)],
    );
    if (result.rowCount !== 1) throw new Error("Evaluation run was not found or is not running");
  }

  async failEvaluation(userId: string, evaluationId: string, failureCode: string): Promise<void> {
    await this.pool.query(
      `UPDATE evaluation_runs SET status = 'failed', failure_code = $3, completed_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'running'`,
      [evaluationId, userId, failureCode],
    );
  }

  async getEvaluation(userId: string, evaluationId: string): Promise<EvaluationRun | null> {
    const result = await this.pool.query<EvaluationRow>(
      `${evaluationSelect} WHERE user_id = $1 AND id = $2`,
      [userId, evaluationId],
    );
    return result.rows[0] ? toEvaluationRun(result.rows[0]) : null;
  }

  async listEvaluations(userId: string, limit: number, cursor?: { createdAt: string; id: string }): Promise<{ evaluations: EvaluationRun[]; hasMore: boolean; lastCursor: { createdAt: string; id: string } | null }> {
    const values: unknown[] = [userId];
    let cursorClause = "";
    if (cursor) {
      values.push(cursor.createdAt, cursor.id);
      cursorClause = " AND (created_at, id) < ($2::timestamptz, $3::text)";
    }
    values.push(limit + 1);
    const result = await this.pool.query<EvaluationRow>(
      `${evaluationSelect} WHERE user_id = $1${cursorClause} ORDER BY created_at DESC, id DESC LIMIT $${values.length}`,
      values,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit);
    const last = rows.at(-1);
    return {
      evaluations: rows.map(toEvaluationRun),
      hasMore,
      lastCursor: last ? { createdAt: last.cursor_created_at, id: last.id } : null,
    };
  }

  async listCases(userId: string, limit: number, cursor?: { createdAt: string; id: string }): Promise<{ cases: InspectionCase[]; hasMore: boolean; lastCursor: { createdAt: string; id: string } | null }> {
    const values: unknown[] = [userId];
    let cursorClause = "";
    if (cursor) {
      values.push(cursor.createdAt, cursor.id);
      cursorClause = " AND (c.created_at, c.id) < ($2::timestamptz, $3::text)";
    }
    values.push(limit + 1);
    const result = await this.pool.query<CaseRow & { cursor_created_at: string }>(
      caseSelect + ` WHERE c.user_id = $1${cursorClause} ORDER BY c.created_at DESC, c.id DESC LIMIT $${values.length}`,
      values,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit);
    const last = rows.at(-1);
    return {
      cases: rows.map(toInspectionCase),
      hasMore,
      lastCursor: last ? { createdAt: last.cursor_created_at, id: last.id } : null,
    };
  }

  async migrate(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock(hashtext('sieve:migrations'))");
      try {
        await client.query(
          "CREATE TABLE IF NOT EXISTS sieve_schema_migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
        );
        const files = (await readdir(fileURLToPath(migrationsDirectory)))
          .filter((filename) => /^\d+_[a-z0-9_-]+\.sql$/.test(filename))
          .sort();

        for (const filename of files) {
          const alreadyApplied = await client.query(
            "SELECT 1 FROM sieve_schema_migrations WHERE filename = $1",
            [filename],
          );
          if (alreadyApplied.rowCount) continue;

          await client.query("BEGIN");
          try {
            await client.query(await readFile(new URL(filename, migrationsDirectory), "utf8"));
            await client.query("INSERT INTO sieve_schema_migrations (filename) VALUES ($1)", [filename]);
            await client.query("COMMIT");
          } catch (error) {
            await client.query("ROLLBACK");
            throw error;
          }
        }
      } finally {
        await client.query("SELECT pg_advisory_unlock(hashtext('sieve:migrations'))");
      }
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

type CaseRow = {
  id: string; network: SuiNetwork; target_kind: "transaction" | "object"; transaction_digest: string | null; object_id: string | null;
  status: InspectionCase["status"]; evidence: EvidenceBundle | null; failure_code: string | null; created_at: Date; updated_at: Date; assessment: DetectorVerdict | null;
};

type EvaluationRow = {
  id: string;
  status: EvaluationRun["status"];
  fixture_set_version: string;
  detector_config: unknown;
  metrics: EvaluationMetrics | null;
  failure_code: string | null;
  created_at: Date;
  completed_at: Date | null;
  cursor_created_at: string;
};

type ThreatMemoryRow = {
  id: string;
  case_id: string;
  pattern: string;
  status: ThreatMemoryWrite["status"];
  normalized_record: unknown;
  walrus_job_id: string | null;
  blob_id: string | null;
  failure_code: string | null;
  created_at: Date;
  updated_at: Date;
  cursor_created_at: string;
};

const threatMemorySelect = `SELECT id, case_id, pattern, status, normalized_record, walrus_job_id, blob_id, failure_code,
  created_at, created_at::text AS cursor_created_at, updated_at FROM threat_memory_writes`;

const evaluationSelect = `SELECT id, status, fixture_set_version, detector_config, metrics, failure_code, created_at,
  created_at::text AS cursor_created_at, completed_at FROM evaluation_runs`;

function toEvaluationRun(row: EvaluationRow): EvaluationRun {
  const rawConfig = row.detector_config && typeof row.detector_config === "object" && !Array.isArray(row.detector_config)
    ? row.detector_config as Record<string, unknown>
    : {};
  const rawJudge = rawConfig.semanticJudge && typeof rawConfig.semanticJudge === "object" && !Array.isArray(rawConfig.semanticJudge)
    ? rawConfig.semanticJudge as Record<string, unknown>
    : null;
  const semanticJudge: EvaluationDetectorConfig["semanticJudge"] = rawJudge?.enabled === false
    ? { enabled: false }
    : (rawJudge?.provider === "openai-responses" || rawJudge?.provider === "groq-responses" || rawJudge?.provider === "nvidia-nim-chat") && typeof rawJudge.model === "string"
      ? { provider: rawJudge.provider, model: rawJudge.model }
      : undefined;
  const detectorConfig: EvaluationDetectorConfig = {
    detectorVersion: typeof rawConfig.detectorVersion === "string" ? rawConfig.detectorVersion : "baseline-rules-v1",
    ...(semanticJudge ? { semanticJudge } : {}),
  };
  return {
    id: row.id,
    status: row.status,
    fixtureSetVersion: row.fixture_set_version,
    detectorConfig,
    metrics: row.metrics ? applyEvaluationThresholds(row.metrics) : null,
    failureCode: row.failure_code,
    createdAt: row.created_at.toISOString(),
    completedAt: row.completed_at?.toISOString() ?? null,
  };
}

function toThreatMemoryWrite(row: ThreatMemoryRow): ThreatMemoryWrite {
  return {
    id: row.id,
    caseId: row.case_id,
    pattern: row.pattern,
    status: row.status,
    normalizedRecord: row.normalized_record,
    walrusJobId: row.walrus_job_id,
    blobId: row.blob_id,
    failureCode: row.failure_code,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

const caseSelect = `SELECT c.id, c.network, c.target_kind, c.transaction_digest, c.object_id, c.status, c.evidence, c.failure_code, c.created_at, c.created_at::text AS cursor_created_at, c.updated_at,
  (SELECT ar.result FROM assessment_revisions ar WHERE ar.case_id = c.id ORDER BY ar.revision DESC LIMIT 1) AS assessment
  FROM inspection_cases c`;

function toInspectionCase(row: CaseRow): InspectionCase {
  const target: LookupTarget = row.target_kind === "transaction"
    ? { kind: "transaction", digest: row.transaction_digest! }
    : { kind: "object", objectId: row.object_id! };
  return { id: row.id, network: row.network, target, status: row.status, evidence: row.evidence, assessment: row.assessment,
    failureCode: row.failure_code, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() };
}
