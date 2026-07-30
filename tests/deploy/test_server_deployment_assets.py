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
    assert "--no-proxy-headers" in unit
    assert "--no-access-log" in unit
    assert "ProtectSystem=strict" in unit


def test_proxy_limits_callers_and_replaces_forwarded_client_address() -> None:
    """Caller-controlled forwarding chains must not reach the application."""
    config = (_DEPLOY_ROOT / "endpoint-platform.nginx.conf").read_text(
        encoding="utf-8"
    )

    assert "server_name endpoint.sosnadmin.local;" in config
    assert "proxy_pass http://127.0.0.1:8000;" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
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
    assert runbook.index("/opt/endpoint-platform/releases /etc/endpoint-platform") < runbook.index(
        "/etc/endpoint-platform/release-commit"
    )
    assert "curl -k" not in runbook
    assert "PRIVATE KEY-----" not in runbook
