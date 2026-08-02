from pathlib import Path


_REPOSITORY_ROOT = Path(__file__).parents[2]


def test_server_runtime_declares_supported_websocket_implementation() -> None:
    """Gateway WSS needs Uvicorn's direct WebSocket runtime dependency."""
    requirements = (_REPOSITORY_ROOT / "requirements-server.txt").read_text(
        encoding="utf-8"
    )

    assert "websockets>=13,<17" in requirements.splitlines()
