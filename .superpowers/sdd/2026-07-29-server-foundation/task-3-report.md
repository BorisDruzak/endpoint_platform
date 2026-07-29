# Task 3 Report: Initial metadata and Alembic migration

## Delivered

- Added SQLAlchemy ownership metadata and one Alembic head,
  `0001_initial`, for the 19 design tables.
- Added UUID primary keys, timezone-aware creation timestamps, bounded text
  identifiers, ownership foreign keys, and digest-only credential storage.
- Added a real PostgreSQL integration test that creates a unique empty database,
  upgrades to head, inspects the resulting schema, downgrades to base, and drops
  the database.
- The migration environment uses the application's asyncpg SQLAlchemy driver and
  Alembic metadata autogeneration reports no drift from the revision.

## Test-first evidence

- The first `python -m pytest tests/server/test_migrations.py -q` run failed both
  tests because no Alembic `script_location` or revision existed.
- A second RED run proved the design's exact `update_targets` name: the test
  expected it while the first implementation still created
  `update_rollout_targets`.
- The final focused run against PostgreSQL 17.10 reported `2 passed`.
- Independent review found that the inspection URL masked passwords and that
  the head check unnecessarily required PostgreSQL. Both test-harness issues
  were corrected; the focused real-PostgreSQL run remained `2 passed`.

## Verification

- `python -m pytest tests/server -q`: `25 passed, 1 skipped`.
- `python -m pytest tests -q`: `138 passed, 1 skipped`.
- Alembic `upgrade head` followed by `alembic check`: `No new upgrade
  operations detected`.
- `python tools/contracts/generate_contract_artifacts.py --check`: passed.
- `python tools/extraction/check_retained_tree.py`: passed.
- `python -m compileall -q endpoint_server endpoint_contracts tools shared`:
  passed.
- `git diff --check`: passed.

The pytest warnings are the existing FastAPI/Starlette deprecations under the
local Python 3.14 runtime.

## Local PostgreSQL and scope

PostgreSQL ran only from an official portable archive under `C:\Temp`, bound to
`127.0.0.1` on a dynamic port. No service was installed and no remote, test, or
production host was contacted. After verification, the server was stopped and
the cluster, both extraction directories, archive, and port file were deleted;
no PostgreSQL process remains. No `pc_agent/` file changed.
