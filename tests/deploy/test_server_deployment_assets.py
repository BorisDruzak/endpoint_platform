from __future__ import annotations

from pathlib import Path


_DEPLOY_ROOT = Path("deploy/server")


def test_api_unit_is_loopback_only_and_hardened() -> None:
    """The public proxy must be the only way to reach the ASGI application."""
    unit = (_DEPLOY_ROOT / "endpoint-platform.service").read_text(encoding="utf-8")

    assert "User=endpoint-platform" in unit
    assert "Group=endpoint-platform" in unit
    assert "EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env" in unit
    assert "--host 127.0.0.1 --port 8000" in unit
    assert "--proxy-headers" in unit
    assert "--no-proxy-headers" not in unit
    assert "--no-access-log" in unit
    assert "--workers 1" in unit
    assert "ProtectSystem=strict" in unit


def test_worker_unit_runs_scheduler_with_api_hardening() -> None:
    """The scheduler runs with the API service's least-privilege boundary."""
    unit = (_DEPLOY_ROOT / "endpoint-platform-worker.service").read_text(
        encoding="utf-8"
    )

    assert "User=endpoint-platform" in unit
    assert "Group=endpoint-platform" in unit
    assert "WorkingDirectory=/opt/endpoint-platform/current" in unit
    assert "EnvironmentFile=/etc/endpoint-platform/endpoint-platform.env" in unit
    assert (
        "ExecStart=/opt/endpoint-platform/current/venv/bin/python "
        "-m endpoint_server.worker" in unit
    )
    assert "Restart=on-failure" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ReadWritePaths=/var/lib/endpoint-platform" in unit


def test_proxy_limits_callers_and_replaces_forwarded_client_address() -> None:
    """Caller-controlled forwarding chains must not reach the application."""
    config = (_DEPLOY_ROOT / "endpoint-platform.nginx.conf").read_text(
        encoding="utf-8"
    )

    assert "server_name endpoint.sosnadmin.local;" in config
    assert "proxy_pass http://127.0.0.1:8000;" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert "location = /agent/v1/connect" in config
    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert 'proxy_set_header Connection "upgrade";' in config
    assert "allow 192.168.100.0/24;" in config
    assert "allow 192.168.101.0/24;" in config
    assert "deny all;" in config


def test_environment_template_keeps_secret_and_network_boundaries() -> None:
    """The checked-in template must not become a usable production secret file."""
    environment = (_DEPLOY_ROOT / "endpoint-platform.env.example").read_text(
        encoding="utf-8"
    )

    assert "DATABASE_URL=postgresql+asyncpg://endpoint_platform:REPLACE_ON_HOST@127.0.0.1:5432/endpoint_platform" in environment
    assert "ALLOWED_AGENT_CIDRS=192.168.100.0/24,192.168.101.0/24" in environment
    assert "ALLOWED_ADMIN_CIDRS=192.168.100.0/24,192.168.101.0/24" in environment
    assert "TRUSTED_PROXY_CIDRS=127.0.0.1/32" in environment
    assert "ENDPOINT_API_WORKERS=1" in environment
    assert "PRIVATE KEY" not in environment


def test_runbook_preserves_secret_and_tls_boundaries() -> None:
    """The operator procedure must retain verified DNS and TLS constraints."""
    runbook = (_DEPLOY_ROOT / "PRODUCTION_RUNBOOK.md").read_text(encoding="utf-8")

    assert "git archive" in runbook
    assert '--output="$releaseArchive"' in runbook
    assert "requirements-server.txt > $releaseArchive" not in runbook
    assert "-verify_hostname endpoint.sosnadmin.local" in runbook
    assert "curl.exe --fail --noproxy '*' --cacert" in runbook
    assert "sudo systemctl disable --now nginx" in runbook
    assert (
        "install -d -o root -g endpoint-platform -m 0710 "
        "/etc/endpoint-platform/secrets" in runbook
    )
    assert runbook.index("/opt/endpoint-platform/releases /etc/endpoint-platform") < runbook.index(
        "/etc/endpoint-platform/release-commit"
    )
    assert "curl -k" not in runbook
    assert "PRIVATE KEY-----" not in runbook
    assert "endpoint-platform-worker.service" in runbook
    assert "enable --now endpoint-platform-worker.service" in runbook
    assert "systemctl is-active postgresql endpoint-platform endpoint-platform-worker nginx" in runbook
    assert "stop endpoint-platform-worker.service" in runbook


def test_runbook_waits_for_loopback_api_readiness_before_enabling_services() -> None:
    """Startup latency must not trigger a false release rollback."""
    runbook = (_DEPLOY_ROOT / "PRODUCTION_RUNBOOK.md").read_text(encoding="utf-8")

    readiness_check = (
        "for attempt in $(seq 1 10); do\n"
        "  if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 "
        "http://127.0.0.1:8000/healthz; then"
    )
    assert readiness_check in runbook
    assert "Endpoint Platform API did not become ready after 10 attempts" in runbook
    assert runbook.index("sudo systemctl start endpoint-platform.service") < runbook.index(
        readiness_check
    ) < runbook.index("sudo systemctl enable --now endpoint-platform-worker.service")
