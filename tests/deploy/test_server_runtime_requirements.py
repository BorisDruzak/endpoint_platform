from pathlib import Path


_REPOSITORY_ROOT = Path(__file__).parents[2]


def test_server_runtime_declares_wsproto_for_proxy_websocket_headers() -> None:
    """Gateway WSS must use the backend that normalizes proxy headers for ASGI."""
    requirements = (_REPOSITORY_ROOT / "requirements-server.txt").read_text(
        encoding="utf-8"
    )
    unit = (_REPOSITORY_ROOT / "deploy/server/endpoint-platform.service").read_text(
        encoding="utf-8"
    )

    assert "wsproto>=1,<2" in requirements.splitlines()
    assert "--ws wsproto" in unit
