from __future__ import annotations

import copy

import pytest

from tools.canary.verify_installed_windows_agent import (
    WindowsPreflightError,
    validate_preflight,
)


def _manifest() -> dict[str, object]:
    return {
        "agent": {
            "platform": "windows_amd64",
            "source_revision": "a" * 40,
            "version": "3.2.16",
            "package_sha256": "b" * 64,
        }
    }


def _valid_projection() -> dict[str, object]:
    return {
        "schema_version": "windows_agent_preflight_v1",
        "agent": {"platform": "windows_amd64"},
        "services": {},
        "runtime": {},
        "msi": {},
        "acl": {},
        "safe_status": {},
        "network": {},
        "completion_proof": {},
    }


def test_valid_projection_is_ready() -> None:
    assert validate_preflight(_valid_projection(), _manifest()) == {
        "status": "READY",
        "platform": "windows_amd64",
    }


def test_unknown_projection_field_fails_closed() -> None:
    projection = copy.deepcopy(_valid_projection())
    projection["credential"] = "forbidden"

    with pytest.raises(WindowsPreflightError, match="schema"):
        validate_preflight(projection, _manifest())
