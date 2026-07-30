from __future__ import annotations

import importlib
import sys


def test_asgi_exposes_health_route_from_valid_environment(monkeypatch, tmp_path) -> None:
    """A deployment entrypoint must construct the real application at import."""
    secret_paths = {
        "DEVICE_TOKEN_PEPPER_FILE": tmp_path / "device-token-pepper",
        "SERVICE_TOKEN_PEPPER_FILE": tmp_path / "service-token-pepper",
        "SESSION_SECRET_FILE": tmp_path / "session-secret",
    }
    for path in secret_paths.values():
        path.write_bytes(b"test-secret")
    for name, path in secret_paths.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+asyncpg://endpoint:secret@127.0.0.1/endpoint"
    )
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://endpoint.sosnadmin.local")
    monkeypatch.setenv("ALLOWED_AGENT_CIDRS", "192.168.101.0/24")
    monkeypatch.setenv("ALLOWED_ADMIN_CIDRS", "192.168.100.0/24")
    monkeypatch.setenv("ARTIFACT_ROOT", str(tmp_path / "artifacts"))

    sys.modules.pop("endpoint_server.asgi", None)
    module = importlib.import_module("endpoint_server.asgi")

    assert "/healthz" in {route.path for route in module.app.routes}
    sys.modules.pop("endpoint_server.asgi", None)
