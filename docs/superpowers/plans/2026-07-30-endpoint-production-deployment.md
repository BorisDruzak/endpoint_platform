# Endpoint Platform Production Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax.

**Goal:** Deploy the verified Endpoint Platform API on 192.168.100.19 behind the existing wildcard certificate with local PostgreSQL and Nginx.

**Architecture:** A small ASGI module turns the existing fail-closed settings factory into a Uvicorn import target. Versioned root-owned releases run as the unprivileged endpoint-platform service on loopback; Nginx is the only network listener and overwrites forwarded client metadata.

**Tech Stack:** Python 3.12, FastAPI, Uvicorn, Alembic, PostgreSQL, systemd, Nginx, OpenSSL, SSH.

## Global Constraints

- Primary repository: BorisDruzak/endpoint_platform. Do not modify Helpdesk.
- Public origin: https://endpoint.sosnadmin.local. No IP URL, TLS bypass, or disabled hostname validation.
- Both allowed CIDR values are exactly 192.168.100.0/24,192.168.101.0/24.
- PostgreSQL and Uvicorn bind only to loopback. Nginx overwrites X-Forwarded-For with $remote_addr.
- Database secrets, application secrets, CA, certificate, and private key never enter Git or the workspace.
- Migrations are forward-only after settings and database validation. Production agent, claim, web_ovpn, and network changes are out of scope.

---

### Task 1: Add a fail-closed ASGI entrypoint

**Files:**

- Create: endpoint_server/asgi.py
- Create: tests/server/test_asgi.py

**Interfaces:** module-level app is the target of "uvicorn endpoint_server.asgi:app"; it consumes only Settings.from_environment() and create_app(settings).

- [ ] **Step 1: Write a failing import-contract test.**

~~~python
import importlib
import sys

from endpoint_server.config import Settings


def test_asgi_uses_fail_closed_settings(monkeypatch):
    captured = {}
    sentinel = object()
    monkeypatch.setattr(Settings, "from_environment", lambda: sentinel)
    monkeypatch.setattr(
        "endpoint_server.main.create_app",
        lambda settings: captured.setdefault("settings", settings) or object(),
    )
    sys.modules.pop("endpoint_server.asgi", None)
    module = importlib.import_module("endpoint_server.asgi")
    assert captured["settings"] is sentinel
    assert module.app is not None
~~~

- [ ] **Step 2: Run the test.**

Run: python -m pytest tests/server/test_asgi.py -q

Expected: FAIL because endpoint_server.asgi does not exist.

- [ ] **Step 3: Implement the minimal import target.**

~~~python
"""Production ASGI import target."""

from endpoint_server.config import Settings
from endpoint_server.main import create_app

app = create_app(Settings.from_environment())
~~~

Do not catch configuration exceptions: invalid settings must prevent Uvicorn serving.

- [ ] **Step 4: Verify and commit.**

Run: python -m pytest tests/server/test_asgi.py tests/server/test_config.py tests/server/test_health.py -q

Expected: PASS.

~~~bash
git add endpoint_server/asgi.py tests/server/test_asgi.py
git commit -m "server: add production ASGI entrypoint"
~~~

### Task 2: Add hardened server and proxy assets

**Files:**

- Create: requirements-server.txt
- Create: deploy/server/endpoint-platform.service
- Create: deploy/server/endpoint-platform-migrate.service
- Create: deploy/server/endpoint-platform.nginx.conf
- Create: deploy/server/endpoint-platform.env.example
- Create: tests/deploy/test_server_deployment_assets.py

**Interfaces:** API unit starts endpoint_server.asgi:app as endpoint-platform on 127.0.0.1:8000. Migration unit runs python -m alembic upgrade head with the same environment. Nginx proxies only to that listener.

- [ ] **Step 1: Write failing static tests.**

~~~python
from pathlib import Path


def test_api_unit_is_loopback_only_and_hardened():
    unit = Path("deploy/server/endpoint-platform.service").read_text()
    assert "User=endpoint-platform" in unit
    assert "EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env" in unit
    assert "--host 127.0.0.1 --port 8000" in unit
    assert "--no-proxy-headers" in unit
    assert "--no-access-log" in unit
    assert "ProtectSystem=strict" in unit


def test_proxy_overwrites_client_address_and_limits_networks():
    config = Path("deploy/server/endpoint-platform.nginx.conf").read_text()
    assert "server_name endpoint.sosnadmin.local;" in config
    assert "proxy_pass http://127.0.0.1:8000;" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert "allow 192.168.100.0/24;" in config
    assert "allow 192.168.101.0/24;" in config
    assert "deny all;" in config
~~~

- [ ] **Step 2: Run the tests.**

Run: python -m pytest tests/deploy/test_server_deployment_assets.py -q

Expected: FAIL with missing deployment files.

- [ ] **Step 3: Add runtime requirements.**

~~~text
alembic
asyncpg
argon2-cffi>=23,<26
cryptography>=46,<47
fastapi>=0.115,<1
SQLAlchemy>=2.0
uvicorn>=0.30,<1
pydantic>=2.12,<3
~~~

Do not include pytest, pc_agent, or Helpdesk requirements.

- [ ] **Step 4: Add API and migration units.**

The API unit includes:

~~~ini
[Service]
Type=simple
User=endpoint-platform
Group=endpoint-platform
WorkingDirectory=/opt/endpoint-platform/current
EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env
ExecStart=/opt/endpoint-platform/current/venv/bin/uvicorn endpoint_server.asgi:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
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
~~~

Migration unit uses the same user, working directory, environment, and hardening; it has Type=oneshot and runs /opt/endpoint-platform/current/venv/bin/python -m alembic upgrade head.

- [ ] **Step 5: Add Nginx and environment templates.**

~~~nginx
listen 443 ssl;
server_name endpoint.sosnadmin.local;
ssl_certificate /etc/nginx/ssl/endpoint.sosnadmin.local.fullchain.pem;
ssl_certificate_key /etc/nginx/ssl/endpoint.sosnadmin.local.key.pem;
allow 127.0.0.1;
allow 192.168.100.0/24;
allow 192.168.101.0/24;
deny all;

location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
}
~~~

Environment template has only REPLACE_ON_HOST in its database URL and exact values PUBLIC_BASE_URL=https://endpoint.sosnadmin.local, ALLOWED_AGENT_CIDRS=192.168.100.0/24,192.168.101.0/24, ALLOWED_ADMIN_CIDRS=192.168.100.0/24,192.168.101.0/24, TRUSTED_PROXY_CIDRS=127.0.0.1/32, and ARTIFACT_ROOT=/var/lib/endpoint-platform/artifacts. It also names the three /etc/endpoint-platform/secrets files required by Settings.

- [ ] **Step 6: Verify and commit.**

Run: python -m pytest tests/deploy/test_server_deployment_assets.py -q; python -m compileall -q endpoint_server; git diff --check

Expected: PASS.

~~~bash
git add requirements-server.txt deploy/server tests/deploy/test_server_deployment_assets.py
git commit -m "deploy: add hardened endpoint service assets"
~~~

### Task 3: Document the controlled production procedure

**Files:**

- Create: deploy/server/PRODUCTION_RUNBOOK.md
- Modify: PLANS.md
- Modify: tests/deploy/test_server_deployment_assets.py

**Interfaces:** consumes Task 2 assets and a clean Git commit; produces versioned release, local database, root-only secrets, validated proxy, migration result, and strict TLS evidence.

- [ ] **Step 1: Extend the failing asset test.**

~~~python
def test_runbook_preserves_secret_and_tls_boundaries():
    runbook = Path("deploy/server/PRODUCTION_RUNBOOK.md").read_text()
    assert "git archive" in runbook
    assert "--verify_hostname endpoint.sosnadmin.local" in runbook
    assert "curl -k" not in runbook
    assert "PRIVATE KEY-----" not in runbook
~~~

- [ ] **Step 2: Run the test.**

Run: python -m pytest tests/deploy/test_server_deployment_assets.py -q

Expected: FAIL because PRODUCTION_RUNBOOK.md is absent.

- [ ] **Step 3: Write exact preparation and host-install steps.**

Require a clean commit and create a release archive without Git metadata or secrets:

~~~powershell
git status --short
git archive --format=tar --prefix=endpoint-platform/ HEAD endpoint_server endpoint_contracts alembic.ini requirements-server.txt | gzip -9 > endpoint-platform-release.tar.gz
~~~

On the host install postgresql, postgresql-client, nginx, python3.12-venv, and python3-pip; create non-login endpoint-platform; create root-owned /opt/endpoint-platform/releases and /etc/endpoint-platform; create writable /var/lib/endpoint-platform/artifacts.

Generate the PostgreSQL password only on the host using openssl rand -hex 32. Create role and database endpoint_platform, store its URL only in root-owned mode 0600 environment file. Generate each Settings secret using openssl rand -hex 48, ownership endpoint-platform:endpoint-platform, mode 0600.

- [ ] **Step 4: Write certificate, migration, smoke, and rollback steps.**

Stream leaf certificate and key from root@192.168.100.12 to root-owned paths on 192.168.100.19 without a workspace file. Append operator-held CA to public fullchain, key mode 0600, and run nginx -t.

Validate settings as endpoint-platform, run the one-shot migration unit, start API, require curl --fail http://127.0.0.1:8000/healthz, then reload Nginx. External TLS probe:

~~~powershell
openssl s_client -connect endpoint.sosnadmin.local:443 -servername endpoint.sosnadmin.local -verify_hostname endpoint.sosnadmin.local -verify_return_error -CAfile <operator-ca-file>
~~~

Close with interactive TTY bootstrap: python -m endpoint_server.auth.bootstrap_admin <username>. Rollback stops API, repoints current to prior verified release, restarts, and repeats loopback plus strict TLS checks. Migration failure is never automatically downgraded.

- [ ] **Step 5: Update plan, verify, and commit.**

Run: python -m pytest tests/deploy/test_server_deployment_assets.py -q; git diff --check

Expected: PASS.

~~~bash
git add deploy/server/PRODUCTION_RUNBOOK.md PLANS.md tests/deploy/test_server_deployment_assets.py
git commit -m "docs: add endpoint production runbook"
~~~

### Task 4: Local release gate and production gate

**Files:**

- Verify: endpoint_server/asgi.py, requirements-server.txt, deploy/server
- Use: deploy/server/PRODUCTION_RUNBOOK.md

- [ ] **Step 1: Run local release verification.**

~~~powershell
python -m pytest tests/server/test_asgi.py tests/server/test_config.py tests/server/test_health.py tests/deploy/test_server_deployment_assets.py -q
python tools/contracts/generate_contract_artifacts.py --check
python -m alembic upgrade head --sql
python -m pytest tests -q
python -m pytest pc_agent/tests/test_linux_release_bundle.py pc_agent/tests/test_linux_packaging.py tests/deploy/test_alt_agent_bundle_install.py tests/deploy/test_alt_agent_package.py -q
git diff --check
~~~

Expected: all tests/ suites pass; PostgreSQL opt-in cases may skip only without ENDPOINT_TEST_POSTGRES_URL. Do not run two known excluded Helpdesk-dependent modules importing unavailable top-level scripts.*; baseline is documented in artifacts/baseline/test-agent-summary.md.

- [ ] **Step 2: Re-check production conditions immediately before mutation.**

Abort if root free space is below 10 GiB, a target port is occupied, or DNS for endpoint.sosnadmin.local differs from 192.168.100.19.

- [ ] **Step 3: Execute runbook and record non-secret handoff evidence.**

Require:

~~~text
systemctl is-active postgresql endpoint-platform nginx -> active
curl --fail http://127.0.0.1:8000/healthz -> success
strict CA and hostname validation -> success
alembic current -> 0010_device_session_last_seen_index
~~~

Bootstrap first administrator only after these checks. Update PLANS.md with deployed commit, migration revision, service/TLS status, and next permitted step: test-agent pilot; commit the non-secret handoff record.

