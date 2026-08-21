"""Static contract for the Endpoint Operations provider release workflow."""

from __future__ import annotations

from pathlib import Path


def test_operations_provider_release_workflow_covers_required_gate_surface() -> None:
    workflow_path = Path(".github/workflows/endpoint-operations-provider.yml")
    assert workflow_path.is_file()

    workflow = workflow_path.read_text(encoding="utf-8")
    for required in (
        "pull_request:",
        "push:",
        "workflow_dispatch:",
        "- main",
        "endpoint_contracts/**",
        "endpoint_server/http/**",
        "endpoint_server/operations/**",
        "endpoint_server/gateway/**",
        "contracts/**",
        "tools/contracts/**",
        "tests/contracts/**",
        "tests/operations/**",
        "tests/gateway/**",
        "python -m pytest tests/contracts tests/operations tests/gateway -q",
        "python tools/contracts/generate_contract_artifacts.py --check",
        "python -m compileall -q endpoint_contracts endpoint_server pc_agent",
        "git diff --check",
        "--junitxml=artifacts/endpoint-operations-provider.xml",
        "actions/upload-artifact@v4",
        "endpoint-operations-provider",
    ):
        assert required in workflow
