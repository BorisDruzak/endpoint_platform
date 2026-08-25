"""Behavioral contract for the redacted Windows diagnostic-canary status."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent.platform.windows.canary_status import (
    CANARY_STATUS_FILENAME,
    CanaryStatusError,
    CanaryStatusWriter,
    read_canary_status,
)
from pc_agent.platform.windows.completion_proof import WindowsCompletionProofWriter


def _release() -> dict[str, str]:
    return {"version": "3.2.22", "source_revision": "a" * 40}


def _marker(command_id: str) -> dict[str, object]:
    return {
        "command_id": command_id,
        "capability": "context.diagnostic.collect",
        "status": "succeeded",
        "duration_ms": 17,
        "result_item_count": 1,
        "timestamp": "2026-08-25T00:00:00+00:00",
    }


def test_writer_persists_only_redacted_truthful_transport_facts(tmp_path: Path) -> None:
    """Removing a transport fact or serializing an origin would weaken preflight proof."""
    writer = CanaryStatusWriter(tmp_path, _release())

    writer.write_transport(
        strict_tls=True,
        hostname_valid=True,
        redirected=False,
        gateway_wss=True,
        http_fallback=False,
    )

    assert read_canary_status(tmp_path) == {
        "schema_version": "endpoint_windows_canary_status_v1",
        "release": _release(),
        "transport": {
            "strict_tls": True,
            "hostname_valid": True,
            "redirected": False,
            "gateway_wss": True,
            "http_fallback": False,
        },
        "capability": "context.diagnostic.collect",
        "completion_proof": None,
    }


def test_writer_marks_disconnected_and_connected_states_explicitly(tmp_path: Path) -> None:
    """A reconnect must clear readiness before a later verified WSS handshake restores it."""
    writer = CanaryStatusWriter(tmp_path, _release())

    writer.write_not_ready()
    assert read_canary_status(tmp_path)["transport"] == {
        "strict_tls": False,
        "hostname_valid": False,
        "redirected": False,
        "gateway_wss": False,
        "http_fallback": False,
    }

    writer.write_wss_ready()
    assert read_canary_status(tmp_path)["transport"] == {
        "strict_tls": True,
        "hostname_valid": True,
        "redirected": False,
        "gateway_wss": True,
        "http_fallback": False,
    }


def test_reader_rejects_unknown_status_fields(tmp_path: Path) -> None:
    """An operator-supplied URL or other field must never enter the evidence projection."""
    path = tmp_path / CANARY_STATUS_FILENAME
    path.write_text(
        json.dumps({"schema_version": "endpoint_windows_canary_status_v1", "endpoint_origin": "forbidden"}),
        encoding="utf-8",
    )

    with pytest.raises(CanaryStatusError, match="schema"):
        read_canary_status(tmp_path)


def test_writer_selects_exact_existing_completion_record(tmp_path: Path) -> None:
    """A previous diagnostic completion cannot satisfy a new post-operation proof."""
    proof_writer = WindowsCompletionProofWriter(tmp_path)
    proof_writer.append_marker(_marker("command-before"))
    proof_writer.append_marker(_marker("command-current"))
    status_writer = CanaryStatusWriter(tmp_path, _release())
    status_writer.write_transport(
        strict_tls=True,
        hostname_valid=True,
        redirected=False,
        gateway_wss=True,
        http_fallback=False,
    )

    status_writer.with_completion("command-current")

    assert read_canary_status(tmp_path)["completion_proof"] == _marker("command-current")


def test_writer_rejects_ambiguous_completion_records(tmp_path: Path) -> None:
    """Duplicated command markers must fail closed rather than pick an arbitrary result."""
    proof_writer = WindowsCompletionProofWriter(tmp_path)
    proof_writer.append_marker(_marker("command-duplicate"))
    proof_writer.append_marker(_marker("command-duplicate"))
    status_writer = CanaryStatusWriter(tmp_path, _release())

    with pytest.raises(CanaryStatusError, match="ambiguous"):
        status_writer.with_completion("command-duplicate")


def test_writer_ignores_non_diagnostic_completion_record(tmp_path: Path) -> None:
    """A baseline result must not overwrite diagnostic-canary completion evidence."""
    marker = {**_marker("command-baseline"), "capability": "context.baseline.collect"}
    WindowsCompletionProofWriter(tmp_path).append_marker(marker)
    status_writer = CanaryStatusWriter(tmp_path, _release())
    status_writer.write_transport(
        strict_tls=True,
        hostname_valid=True,
        redirected=False,
        gateway_wss=True,
        http_fallback=False,
    )

    status_writer.with_completion("command-baseline")

    assert read_canary_status(tmp_path)["completion_proof"] is None
