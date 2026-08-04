"""Network-free verification contracts for the neutral runtime."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from uuid import UUID

import aiohttp
import pytest

from pc_agent.device_credential import DeviceCredentialError, read_device_credential
from pc_agent.runtime.application import RuntimeSettings
from pc_agent.runtime.local_state import LOCAL_STATE_SCHEMA_VERSION
from pc_agent.runtime.verification import run_verify


_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000501")


def _valid_settings(tmp_path: Path) -> RuntimeSettings:
    data_root = tmp_path / "data"
    install_root = tmp_path / "install"
    data_root.mkdir()
    install_root.mkdir()
    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test-only CA fixture", encoding="ascii")
    (data_root / "device-credential").write_text("c" * 43 + "\n", encoding="ascii")
    (data_root / "enrollment-identity.json").write_text(
        json.dumps(
            {
                "device_id": str(_DEVICE_ID),
                "schema_version": "endpoint_enrollment_identity_v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (install_root / "current.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.84",
            }
        ),
        encoding="utf-8",
    )
    return RuntimeSettings(
        data_root=data_root,
        install_root=install_root,
        ca_file=ca_file,
        endpoint_origin="https://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )


def test_verify_migrates_local_database_without_opening_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A verify regression must not turn a local preflight into a network call."""
    settings = _valid_settings(tmp_path)

    def network_forbidden(*_args, **_kwargs):
        raise AssertionError("verify mode attempted to create an HTTP client")

    monkeypatch.setattr(aiohttp, "ClientSession", network_forbidden)

    assert run_verify(settings) == 0
    with sqlite3.connect(settings.data_root / "storage.db") as connection:
        assert connection.execute(
            "SELECT schema_version FROM endpoint_runtime_schema WHERE singleton = 1"
        ).fetchone() == (LOCAL_STATE_SCHEMA_VERSION,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)


def test_verify_accepts_the_strict_windows_current_selector(tmp_path: Path) -> None:
    """The LocalSystem updater verifies a Windows candidate against this selector."""
    settings = _valid_settings(tmp_path)
    (settings.install_root / "current.json").write_text(
        '{"version":"3.2.10"}', encoding="utf-8"
    )

    assert run_verify(settings) == 0


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        (
            "enrollment-identity.json",
            {
                "device_id": "not-a-uuid",
                "schema_version": "endpoint_enrollment_identity_v1",
            },
        ),
        ("current.json", {"version": "3.1.84", "previous": "3.1.80"}),
    ],
)
def test_verify_rejects_malformed_enrollment_identity_or_update_selector(
    tmp_path: Path, filename: str, payload: dict[str, object]
) -> None:
    """Malformed durable state must fail preflight instead of starting the agent."""
    settings = _valid_settings(tmp_path)
    target_root = (
        settings.data_root
        if filename == "enrollment-identity.json"
        else settings.install_root
    )
    (target_root / filename).write_text(json.dumps(payload), encoding="utf-8")

    assert run_verify(settings) == 1


def test_verify_rejects_missing_enrollment_identity_without_using_legacy_machine_id(
    tmp_path: Path,
) -> None:
    """A legacy machine UUID must never substitute for the server Device.id."""
    settings = _valid_settings(tmp_path)
    (settings.data_root / "enrollment-identity.json").unlink()
    (settings.data_root / "identity.json").write_text(
        json.dumps(
            {
                "version": 2,
                "uuid": "00000000-0000-4000-8000-000000000509",
                "machine_id": "00000000-0000-4000-8000-000000000509",
                "install_id": "00000000-0000-4000-8000-000000000510",
                "machine_id_source": "test-fixture",
                "token": None,
            }
        ),
        encoding="utf-8",
    )

    assert run_verify(settings) == 1


def test_verify_rejects_non_https_endpoint_configuration(tmp_path: Path) -> None:
    """An HTTP controller origin must fail before any local or network startup."""
    valid = _valid_settings(tmp_path)
    settings = RuntimeSettings(
        data_root=valid.data_root,
        install_root=valid.install_root,
        ca_file=valid.ca_file,
        endpoint_origin="http://endpoint.sosnadmin.local",
        transport_mode="gateway_http_pull",
    )

    assert run_verify(settings) == 1


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\r\n"])
def test_neutral_credential_reader_accepts_exact_token_with_optional_lf(
    tmp_path: Path, suffix: bytes
) -> None:
    path = tmp_path / "device-credential"
    path.write_bytes(b"c" * 43 + suffix)

    assert read_device_credential(path) == "c" * 43


@pytest.mark.parametrize(
    "payload",
    [
        b"c" * 42,
        b"c" * 44,
        b"c" * 43 + b"\n\n",
        b"c" * 43 + b"\r",
        b"c" * 42 + b" ",
        b"\xff" * 43,
    ],
)
def test_neutral_credential_reader_rejects_malformed_file(
    tmp_path: Path, payload: bytes
) -> None:
    path = tmp_path / "device-credential"
    path.write_bytes(payload)

    with pytest.raises(DeviceCredentialError):
        read_device_credential(path)
