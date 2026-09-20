from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pc_agent.platform.windows.tray_status import (
    TRAY_STATUS_FILENAME,
    TRAY_STATUS_SCHEMA,
    TrayStatusError,
    TrayStatusWriter,
    read_tray_status,
)


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def _data_root(tmp_path: Path) -> Path:
    root = tmp_path / "Agent"
    root.mkdir()
    return root


def _status_path(data_root: Path) -> Path:
    return data_root.parent / "Tray" / TRAY_STATUS_FILENAME


def test_writer_publishes_only_fixed_redacted_schema(tmp_path: Path) -> None:
    protected: list[Path] = []
    data_root = _data_root(tmp_path)
    writer = TrayStatusWriter(
        data_root,
        "3.2.51",
        now=lambda: NOW,
        protect=lambda path: protected.append(path),
    )

    writer.publish(
        agent_state="running",
        endpoint_state="connected",
        update_state="up_to_date",
    )

    path = _status_path(data_root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "agent_state": "running",
        "endpoint_state": "connected",
        "observed_at": NOW.isoformat(),
        "reason_code": None,
        "schema_version": TRAY_STATUS_SCHEMA,
        "update_state": "up_to_date",
        "version": "3.2.51",
    }
    assert protected == [path]
    assert "credential" not in json.dumps(payload)
    assert "identity" not in json.dumps(payload)
    assert "endpoint_origin" not in json.dumps(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "schema_version": TRAY_STATUS_SCHEMA,
            "version": "3.2.51",
            "agent_state": "running",
            "endpoint_state": "connected",
            "update_state": "up_to_date",
            "observed_at": NOW.isoformat(),
            "reason_code": None,
            "credential": "forbidden",
        },
    ],
)
def test_reader_rejects_malformed_or_extended_payload(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    data_root = _data_root(tmp_path)
    path = _status_path(data_root)
    path.parent.mkdir()
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(TrayStatusError, match="schema"):
        read_tray_status(data_root, now=NOW)


def test_reader_rejects_stale_or_future_observation(tmp_path: Path) -> None:
    data_root = _data_root(tmp_path)
    writer = TrayStatusWriter(data_root, "3.2.51", now=lambda: NOW, protect=lambda _path: None)
    writer.publish(
        agent_state="running",
        endpoint_state="connected",
        update_state="up_to_date",
    )

    with pytest.raises(TrayStatusError, match="stale"):
        read_tray_status(data_root, now=NOW + timedelta(seconds=121))

    payload = json.loads(_status_path(data_root).read_text(encoding="utf-8"))
    payload["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    _status_path(data_root).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TrayStatusError, match="future"):
        read_tray_status(data_root, now=NOW)


def test_writer_rejects_reparse_status_directory(tmp_path: Path) -> None:
    data_root = _data_root(tmp_path)
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    tray_root = data_root.parent / "Tray"
    try:
        os.symlink(redirected, tray_root, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink unavailable: {error}")

    writer = TrayStatusWriter(data_root, "3.2.51", now=lambda: NOW, protect=lambda _path: None)
    with pytest.raises(TrayStatusError, match="reparse"):
        writer.publish(
            agent_state="running",
            endpoint_state="connected",
            update_state="up_to_date",
        )
