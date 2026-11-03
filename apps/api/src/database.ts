import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";

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
