# SecureShift

SecureShift is a role-aware workforce scheduling service for teams that need auditable assignment and completion workflows. The reference implementation uses Express, TypeScript, Zod validation, JWT access tokens, scrypt password hashing, OTP challenges, SQLite in WAL mode for deterministic local development, and an async PostgreSQL adapter for managed deployments. The persistence layer is deliberately isolated so storage changes do not alter HTTP contracts.

## Architecture

```mermaid
flowchart LR
  Mobile[Expo mobile client] --> API[Express API]
  API --> Auth[JWT + OTP service]
  API --> Policy[RBAC policy middleware]
  API --> Repo{Repository boundary}
  Repo --> SQLite[(SQLite local adapter)]
  Repo --> Postgres[(Async PostgreSQL adapter)]
  API --> Audit[Append-only audit log]
  Policy --> Repo
```

## Structural overview

```text
src/
  app.ts       HTTP routes, validation, error boundary
  security.ts  password, JWT, OTP primitives
  db.ts        SQLite schema and connection bootstrap
  repository.ts sync SQLite + async PostgreSQL implementations
  server.ts    process entrypoint
tests/         contract-level API tests
mobile/       client integration can be added without changing API contracts
```

## Workflow

1. A manager authenticates and receives a short-lived JWT.
2. The manager creates a shift; the API rejects malformed or overlapping time boundaries.
3. A manager assigns only a user with the `worker` role.
4. The assignee completes the shift, or a manager completes it on their behalf.
5. Every privileged mutation creates an audit event with actor, entity, and metadata.

## Security decisions

- Passwords use `scrypt` with a random per-user salt and constant-time verification. The JWT secret must be at least 32 characters in production.
- JWTs are issuer-scoped and expire after two hours.
- OTP codes are stored as SHA-256 digests and expire after five minutes.
- Role checks happen in middleware and ownership is checked again at the state transition boundary.
- The development response exposes `devCode` for local testing; it is disabled when `NODE_ENV=production`.

## Run locally

Requires Node.js 22.5 or newer because the local adapter uses the built-in `node:sqlite` module.

```bash
npm install
cp .env.example .env
npm run dev
# http://localhost:4010/health
npm test
```

## Trade-offs and next steps

SQLite keeps onboarding deterministic and makes the test suite self-contained. A production deployment should use MongoDB or PostgreSQL with migrations, a real SMS provider, refresh-token rotation, and an outbox-backed notification worker. The API intentionally keeps state transitions explicit so those changes do not alter client behavior.

## Production adapters

Set `DB_URL` or `SUPABASE_DB_URL` to route all user, shift, OTP, and audit operations through the async PostgreSQL repository. The repository creates the required tables and indexes on startup; use a migration tool for stricter production change control. When neither variable is set, local tests and development use the synchronous Node SQLite adapter. The `/health` response reports the selected mode, and startup refuses a future configuration that requests Postgres while exposing a SQLite route repository.

Set `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `SUPABASE_STORAGE_BUCKET` (or `STORAGE_BUCKET`) for signed uploads. The service-role key is server-only and must never be placed in the Expo client.
