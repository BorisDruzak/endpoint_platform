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
        "agent": {
            "platform": "windows_amd64",
            "source_revision": "a" * 40,
            "version": "3.2.16",
        },
        "services": {
            "agent": {
                "name": "EndpointAgent",
                "start_mode": "Automatic",
                "state": "Running",
                "account": "NT AUTHORITY\\LocalService",
                "pid_present": True,
                "host": {
                    "path": "C:\\Program Files\\Endpoint Platform\\Agent\\endpoint-agent-service.exe",
                    "regular": True,
                    "reparse": False,
                    "fixed_entrypoint": True,
                },
                "runtime_children": [{
                    "path": "C:\\Program Files\\Endpoint Platform\\Agent\\versions\\3.2.16\\pc_agent.exe",
                    "regular": True,
                    "reparse": False,
                    "service_child": True,
                    "safe_command": True,
                }],
            },
            "updater": {
                "name": "EndpointAgentUpdater",
                "start_mode": "Manual",
                "state": "Stopped",
                "account": "LocalSystem",
                "regular": True,
                "listener": False,
                "safe_command": True,
            },
        },
        "runtime": {
            "selector_regular": True,
            "selector_reparse": False,
            "selector_version": "3.2.16",
            "selector_source_revision": "a" * 40,
            "selected_runtime_present": True,
            "http_fallback": False,
            "helpdesk_reference": False,
        },
        "msi": {"version": "3.2.16", "sha256": "b" * 64, "owned_files": True},
        "acl": {
            "data_root_protected": True,
            "required_principals": True,
            "ordinary_user_read": False,
            "protected_file_regular": True,
            "protected_file_reparse": False,
        },
        "safe_status": {"service": "running", "identity_present": True},
        "network": {
            "strict_tls": True,
            "hostname_valid": True,
            "redirected": False,
            "gateway_wss": True,
            "capability": "context.diagnostic.collect",
        },
        "completion_proof": {
            "command_id": "00000000-0000-4000-8000-000000000001",
            "capability": "context.diagnostic.collect",
            "status": "succeeded",
            "duration_ms": 1,
            "result_item_count": 1,
            "timestamp": "2026-08-24T00:00:00+00:00",
        },
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


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["services"].pop("agent"),
        lambda value: value["services"]["agent"].update(account="LocalSystem"),
        lambda value: value["services"]["agent"].update(start_mode="Manual"),
        lambda value: value["services"]["agent"].update(state="Stopped"),
        lambda value: value["services"]["agent"]["host"].update(regular=False),
        lambda value: value["services"]["agent"]["host"].update(reparse=True),
        lambda value: value["services"]["agent"].update(runtime_children=[]),
        lambda value: value["services"]["agent"].update(runtime_children=[{}, {}]),
        lambda value: value["runtime"].update(selector_source_revision="c" * 40),
        lambda value: value["msi"].update(version="3.2.17"),
        lambda value: value["msi"].update(sha256="d" * 64),
        lambda value: value["acl"].update(data_root_protected=False),
        lambda value: value["acl"].update(ordinary_user_read=True),
        lambda value: value["services"]["updater"].update(state="Running"),
        lambda value: value["services"]["updater"].update(start_mode="Automatic"),
        lambda value: value["services"]["updater"].update(listener=True),
        lambda value: value["runtime"].update(http_fallback=True),
        lambda value: value["runtime"].update(helpdesk_reference=True),
        lambda value: value["network"].update(strict_tls=False),
        lambda value: value["network"].update(hostname_valid=False),
        lambda value: value["network"].update(capability="context.baseline.collect"),
    ],
)
def test_unsafe_projection_is_rejected(mutate) -> None:
    projection = _valid_projection()
    mutate(projection)

    with pytest.raises(WindowsPreflightError):
        validate_preflight(projection, _manifest())
