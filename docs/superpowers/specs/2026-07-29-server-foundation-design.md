# Endpoint Server Foundation Design

## Scope

6A-2 creates the standalone FastAPI/PostgreSQL foundation for future Gateway work. It does not add enrolment, agent commands, admin authentication, UI, or production deployment.

## Components

- `endpoint_server/config.py` parses settings and safely reads required secret files.
- `endpoint_server/db/` owns async SQLAlchemy engine/session construction, metadata, and Alembic migrations.
- `endpoint_server/health/` owns `GET /healthz` only.
- `endpoint_server/main.py` exposes `create_app(settings: Settings) -> FastAPI`.
- `endpoint_server/worker.py` exposes an interruptible, no-op-safe `run_worker(settings)` for future jobs.

Routes use injected sessions; they do not create engines or read environment variables. No raw token or service credential is stored by the initial schema.

## Configuration

Required values are `DATABASE_URL`, `PUBLIC_BASE_URL`, `DEVICE_TOKEN_PEPPER_FILE`, `SERVICE_TOKEN_PEPPER_FILE`, `SESSION_SECRET_FILE`, `ALLOWED_AGENT_CIDRS`, `ALLOWED_ADMIN_CIDRS`, and `ARTIFACT_ROOT`. Production URL is HTTPS at `endpoint.sosnadmin.local`; CIDRs are parsed with `ipaddress`. Secrets are file-only and startup rejects missing, empty, directory, symlink, or group/world-readable files.

## Health

`GET /healthz` executes `SELECT 1`. Success returns HTTP 200 with `status: ok`, `service: endpoint-platform`, `database: ok`, and version. Database failure returns HTTP 503 with `database: unavailable` and no connection, SQL, secret, or exception detail.

## Database

The initial Alembic revision creates ownership-zone tables for admin users/sessions, service clients/credentials, audit events, devices/credentials/instances/sessions, enrolment campaigns/claims/events, commands/deliveries/results, and update builds/rollouts/targets/reports. Tables use UUID primary keys, UTC timestamps and bounded identifiers. Future features own behaviour; this increment only establishes schema.

Migration tests run upgrade/downgrade against a disposable local PostgreSQL database: upgrade from empty reaches one head and expected tables; downgrade leaves no application tables. This is development-only, not production or `test-agent`.

## Acceptance

Tests cover safe configuration, health success/failure, worker lifecycle, and empty-DB migration upgrade/downgrade. Completion requires focused server tests, full standalone `tests`, schema check, extraction verifier, compilation, `git diff --check`, no `pc_agent` changes, and no remote-machine action.
