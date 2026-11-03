import { readdir, readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import type { DetectorVerdict, EvidenceBundle, InspectionCase, LookupTarget, SuiNetwork } from "@sieve/contracts";

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

  async saveAssessment(userId: string, caseId: string, verdict: DetectorVerdict): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const owned = await client.query("SELECT id FROM inspection_cases WHERE id = $1 AND user_id = $2 FOR UPDATE", [caseId, userId]);
      if (owned.rowCount !== 1) throw new Error("Inspection case was not found");
      const revision = await client.query<{ revision: number | null }>("SELECT max(revision) AS revision FROM assessment_revisions WHERE case_id = $1", [caseId]);
      await client.query(
        `INSERT INTO assessment_revisions (id, case_id, revision, detector_version, outcome, result)
         VALUES ($1, $2, $3, 'baseline-rules-v1', $4, $5::jsonb)`,
        [randomUUID(), caseId, (revision.rows[0]?.revision ?? 0) + 1, verdict.outcome, JSON.stringify(verdict)],
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

  async listCases(userId: string, limit: number, offset: number): Promise<InspectionCase[]> {
    const result = await this.pool.query<CaseRow>(caseSelect + " WHERE c.user_id = $1 ORDER BY c.created_at DESC, c.id DESC LIMIT $2 OFFSET $3", [userId, limit, offset]);
    return result.rows.map(toInspectionCase);
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

const caseSelect = `SELECT c.id, c.network, c.target_kind, c.transaction_digest, c.object_id, c.status, c.evidence, c.failure_code, c.created_at, c.updated_at,
  (SELECT ar.result FROM assessment_revisions ar WHERE ar.case_id = c.id ORDER BY ar.revision DESC LIMIT 1) AS assessment
  FROM inspection_cases c`;

function toInspectionCase(row: CaseRow): InspectionCase {
  const target: LookupTarget = row.target_kind === "transaction"
    ? { kind: "transaction", digest: row.transaction_digest! }
    : { kind: "object", objectId: row.object_id! };
  return { id: row.id, network: row.network, target, status: row.status, evidence: row.evidence, assessment: row.assessment,
    failureCode: row.failure_code, createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString() };
}
