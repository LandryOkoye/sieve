# Database

PostgreSQL stores user identity references, inspection cases, assessment revisions, Walrus write state, evaluation runs, and audit events. Walrus remains the durable cross-session memory store; this database records application ownership and operation state.

The first migration is transactional SQL. Apply migrations in ascending filename order and record each applied filename in the deployment's migration process. The API must scope every case and memory-reference query to the authenticated user ID.

`app_users` stores an external identity issuer and subject, not credentials. The authentication provider remains a deployment choice. Case evidence is stored as JSONB so refreshes and retries can recover the same provenance bundle; define retention and deletion behavior before production deployment.
