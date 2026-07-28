# Endpoint Server Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` task-by-task.

**Goal:** Build the 6A-2 FastAPI/PostgreSQL foundation without Gateway business behaviour.

**Architecture:** One `endpoint_server` package contains validated settings, async database session ownership, health routing, a no-op worker, and Alembic schema. Tests use injected sessions and a disposable local PostgreSQL database.

**Tech Stack:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy async, asyncpg, Alembic, pytest.

## Constraints

- Do not modify `pc_agent`, create enrolment/command/auth/UI features, contact remote hosts, or deploy infrastructure.
- Production settings fail closed for missing or unsafe file secrets.
- PostgreSQL migration tests use only disposable local state.

## Task 1: Add settings and dependency metadata

**Files:** Create `endpoint_server/config.py`, `endpoint_server/__init__.py`, `tests/server/test_config.py`; modify `requirements-ci.txt`.

- [ ] Write failing tests for HTTPS URL, CIDR parsing, missing/empty/symlink/world-readable secret rejection, and safe secret loading.
- [ ] Run `python -m pytest tests/server/test_config.py -q`; expect import failure.
- [ ] Implement immutable `Settings` with `from_environment()` and `load_secret_file(path: Path) -> bytes`; require all eight settings and pin `fastapi>=0.115,<1`, `uvicorn>=0.30,<1`.
- [ ] Re-run focused tests; commit `feat: add endpoint server settings`.

## Task 2: Add async session layer and health endpoint

**Files:** Create `endpoint_server/db/base.py`, `endpoint_server/db/session.py`, `endpoint_server/health/routes.py`, `endpoint_server/main.py`, `endpoint_server/worker.py`, `tests/server/test_health.py`.

- [ ] Write failing ASGI tests: injected successful session returns exact 200 payload; failed `SELECT 1` returns generic 503; worker exits after cancellation.
- [ ] Run `python -m pytest tests/server/test_health.py -q`; expect import failure.
- [ ] Implement `create_app(settings)`, injected `AsyncSession` dependency, `GET /healthz`, and interruptible no-op worker; do not reveal exceptions.
- [ ] Re-run focused tests and compile; commit `feat: add endpoint health foundation`.

## Task 3: Add initial metadata and Alembic migration

**Files:** Create `endpoint_server/db/models/__init__.py`, model modules, `alembic.ini`, `endpoint_server/db/migrations/env.py`, `endpoint_server/db/migrations/versions/0001_initial.py`, `tests/server/test_migrations.py`.

- [ ] Write failing tests that run upgrade from empty local PostgreSQL, assert the complete expected table set, assert one head revision, downgrade base, and assert application tables absent.
- [ ] Run `python -m pytest tests/server/test_migrations.py -q`; expect migration import/upgrade failure.
- [ ] Implement ownership-zone SQLAlchemy metadata and one Alembic revision for the exact tables named in the design; use UUID identifiers, UTC timestamps, bounded identifiers and no raw credential columns.
- [ ] Run migration tests against the disposable local PostgreSQL; commit `feat: add endpoint server schema`.

## Task 4: Run acceptance checks

- [ ] Run `python -m pytest tests/server -q`, `python -m pytest tests -q`, `python tools/contracts/generate_contract_artifacts.py --check`, `python tools/extraction/check_retained_tree.py`, `python -m compileall -q endpoint_server endpoint_contracts tools shared`, and `git diff --check`.
- [ ] Inspect changed paths and confirm no `pc_agent/` file changed.
- [ ] Commit any required test/documentation corrections only after a new failing test proves the change.

## Self-review

- The tasks cover every design component and retain 6A-2 scope boundaries.
- Each new production behaviour begins with a focused failing test.
- Migration acceptance uses real disposable PostgreSQL rather than SQLite.
