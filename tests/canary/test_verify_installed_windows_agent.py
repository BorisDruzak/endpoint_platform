from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tools.canary.verify_installed_windows_agent import (
    CompletionExpectation,
    WindowsPreflightError,
    validate_preflight,
)


COLLECTOR = Path(__file__).resolve().parents[2] / "tools" / "canary" / "Collect-WindowsAgentPreflight.ps1"


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
            "status_artifact_protected": True,
            "provenance_artifact_protected": True,
            "msi_artifact_protected": True,
        },
        "safe_status": {
            "service": "running",
            "identity_present": True,
            "regular": True,
            "reparse": False,
            "release_version": "3.2.16",
            "release_source_revision": "a" * 40,
        },
        "network": {
            "strict_tls": True,
            "hostname_valid": True,
            "redirected": False,
            "gateway_wss": True,
            "http_fallback": False,
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
        lambda value: value["network"].update(http_fallback=True),
        lambda value: value["network"].update(capability="context.baseline.collect"),
        lambda value: value["safe_status"].update(regular=False),
        lambda value: value["safe_status"].update(reparse=True),
        lambda value: value["acl"].update(status_artifact_protected=False),
        lambda value: value["acl"].update(provenance_artifact_protected=False),
        lambda value: value["acl"].update(msi_artifact_protected=False),
    ],
)
def test_unsafe_projection_is_rejected(mutate) -> None:
    projection = _valid_projection()
    mutate(projection)

    with pytest.raises(WindowsPreflightError):
        validate_preflight(projection, _manifest())


def test_collector_has_fixed_services_and_never_reads_protected_files() -> None:
    source = COLLECTOR.read_text(encoding="utf-8")

    assert "EndpointAgent" in source
    assert "EndpointAgentUpdater" in source
    assert "Get-Content.*device-credential" not in source
    assert "Get-Content.*enrollment-identity.json" not in source
    assert "ConvertTo-CanonicalServiceStartMode" in source
    assert "installer-provenance.json" in source
    assert "canary-status.json" in source
    assert "sha256 = ''" not in source
    assert "$RequireCompletion" in source
    assert "S-1-5-18" in source
    assert "S-1-5-32-544" in source
    assert "ExpectedEndpointHost" in source
    assert "Split-Path -Parent $current.FullName" in source
    assert "$current.Parent" not in source
    assert "$ConsoleHostPath" in source
    assert "$completionStatus = Read-CanaryStatus" in source


def test_preflight_collector_accepts_json_int32_completion_metrics() -> None:
    """Small JSON numbers deserialize as Int32 in PowerShell 7 on Windows."""
    source = COLLECTOR.read_text(encoding="utf-8")

    assert "($Completion.duration_ms -is [int] -or $Completion.duration_ms -is [long])" in source
    assert "($Completion.result_item_count -is [int] -or $Completion.result_item_count -is [long])" in source


def test_preflight_allows_no_completion_before_an_operation() -> None:
    """A readiness gate cannot require evidence that only the future operation can create."""
    projection = _valid_projection()
    projection["completion_proof"] = None

    assert validate_preflight(projection, _manifest()) == {
        "status": "READY",
        "platform": "windows_amd64",
    }


def test_post_operation_requires_exact_succeeded_diagnostic_completion() -> None:
    """A stale, failed, or unrelated result must not prove a newly scheduled canary."""
    expectation = CompletionExpectation(
        command_id="00000000-0000-4000-8000-000000000001",
        capability="context.diagnostic.collect",
    )
    projection = _valid_projection()

    assert validate_preflight(
        projection, _manifest(), require_completion=expectation
    )["status"] == "READY"
    projection["completion_proof"] = None
    with pytest.raises(WindowsPreflightError, match="completion"):
        validate_preflight(projection, _manifest(), require_completion=expectation)
