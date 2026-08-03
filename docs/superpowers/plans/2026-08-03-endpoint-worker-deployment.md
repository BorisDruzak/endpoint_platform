# Endpoint Worker Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the existing Endpoint Platform background worker as a hardened, independently managed systemd service so periodic Device Context collection runs on the controller.

**Architecture:** Add one non-secret systemd unit alongside the API and migration units. It runs `endpoint_server.worker` from the active immutable release under the same service account and environment file as the API, while retaining a narrow writable-state boundary. The production runbook installs, enables, verifies, and rolls back the worker unit together with the API assets.

**Tech Stack:** systemd, Python 3.12 virtual environment, existing `endpoint_server.worker`, pytest deployment contract tests.

## Global Constraints

- The worker must run as `endpoint-platform:endpoint-platform` from `/opt/endpoint-platform/current`.
- Configuration comes only from `/etc/endpoint-platform/endpoint-platform.env`; no secret may appear in the unit or runbook command line.
- The worker must use `python -m endpoint_server.worker`, restart only on failure, and retain the API unit's systemd hardening and `/var/lib/endpoint-platform` writable boundary.
- Deployment remains reversible: the runbook must install the worker asset with the existing service assets, enable it only after migrations/API startup, and stop it when rolling back the release.
- Tests must assert the contract from the checked-in unit and runbook before deployment.

---

### Task 1: Ship the Endpoint worker service asset and operator procedure

**Files:**

- Create: `deploy/server/endpoint-platform-worker.service`
- Modify: `tests/deploy/test_server_deployment_assets.py`
- Modify: `deploy/server/PRODUCTION_RUNBOOK.md`

**Interfaces:**

- Consumes: `endpoint_server.worker` module entry point and `/etc/endpoint-platform/endpoint-platform.env`.
- Produces: `endpoint-platform-worker.service`, a systemd unit that activates the scheduler; an operator procedure that installs, enables, checks, and stops it with the current release.

- [x] **Step 1: Write the failing deployment contract test**

```python
def test_worker_unit_runs_scheduler_with_api_hardening() -> None:
    unit = (_DEPLOY_ROOT / "endpoint-platform-worker.service").read_text(encoding="utf-8")
    assert "User=endpoint-platform" in unit
    assert "Group=endpoint-platform" in unit
    assert "WorkingDirectory=/opt/endpoint-platform/current" in unit
    assert "EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env" in unit
    assert "ExecStart=/opt/endpoint-platform/current/venv/bin/python -m endpoint_server.worker" in unit
    assert "Restart=on-failure" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/lib/endpoint-platform" in unit
```

Extend the existing runbook test so it requires `endpoint-platform-worker.service`, `enable --now endpoint-platform-worker.service`, an active-state check that includes the worker, and `stop endpoint-platform-worker.service` in the rollback section.

- [x] **Step 2: Run the focused test and confirm RED**

Run: `python -m pytest tests/deploy/test_server_deployment_assets.py -q`

Expected: FAIL because `deploy/server/endpoint-platform-worker.service` is absent and the worker deployment assertions are not yet satisfied.

- [x] **Step 3: Add the minimal worker unit and runbook changes**

Create the unit with the same account, directory, environment, hardening, and writable path as `endpoint-platform.service`, but use the bounded single-process worker command:

```ini
[Service]
Type=simple
User=endpoint-platform
Group=endpoint-platform
WorkingDirectory=/opt/endpoint-platform/current
EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env
ExecStart=/opt/endpoint-platform/current/venv/bin/python -m endpoint_server.worker
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/endpoint-platform
```

Update the runbook's asset copy/install command to include this file, enable it after successful migration/API start, include it in `systemctl is-active`, and stop it before changing the `current` release symlink during rollback.

- [x] **Step 4: Run focused checks and confirm GREEN**

Run: `python -m pytest tests/deploy/test_server_deployment_assets.py -q`

Expected: PASS with every server deployment asset contract test green.

- [x] **Step 5: Commit**

```powershell
git add deploy/server/endpoint-platform-worker.service deploy/server/PRODUCTION_RUNBOOK.md tests/deploy/test_server_deployment_assets.py docs/superpowers/plans/2026-08-03-endpoint-worker-deployment.md
git commit -m "deploy: add endpoint worker service"
```
