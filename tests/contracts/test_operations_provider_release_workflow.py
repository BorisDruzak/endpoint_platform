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
        "endpoint_server/context/**",
        "endpoint_server/device_binding/**",
        "ENDPOINT_TEST_POSTGRES_URL",
        "postgres:16",
        "contracts/**",
        "tools/contracts/**",
        "tests/contracts/**",
        "tests/operations/**",
        "tests/gateway/**",
        "tests/context/**",
        "python -m pytest tests pc_agent/tests -q -o faulthandler_timeout=120 --ignore=pc_agent/tests/windows",
        '"pc_agent/**"',
        '"packaging/**"',
        '"tools/**"',
        '"tests/**"',
        '"requirements/**"',
        '"requirements-ci.txt"',
        '"pyproject.toml"',
        '"pytest.ini"',
        "if: always()",
        "if-no-files-found: error",
        "fetch-depth: 0",
        "python tools/contracts/generate_contract_artifacts.py --check",
        "python -m compileall -q endpoint_contracts endpoint_server pc_agent",
        "git diff --check",
        "--junitxml=artifacts/endpoint-operations-provider.xml",
        "python -m pytest -q tests/build --junitxml=artifacts/linux-build.xml",
        "            artifacts/linux-build.xml",
        "actions/upload-artifact@v4",
        "endpoint-operations-provider",
        "windows-release-gate:",
    ):
        assert required in workflow

    windows_job = workflow.split("\n  windows-release-gate:", 1)[1]
    for required in (
        "runs-on: windows-latest",
        "-r requirements/build-windows.txt",
        "          pc_agent/tests/windows",
        "tests/deploy/test_keycloak_ad_pilot.py",
        "tests/packaging/test_installation_notification_stage.py",
        "tests/packaging/test_setup_preflight_process.py",
        "tests/packaging/test_staged_cleanup_retry.py",
        "tests/packaging/test_support_access_signing.py",
        "tests/packaging/test_support_staged_payload.py",
        "tests/canary/test_legacy_fixture_schema.py",
        "--junitxml=artifacts/windows-release-gate.xml",
    ):
        assert required in windows_job


def test_ci_requirements_pin_fastapi_to_the_committed_contract_renderer() -> None:
    requirements = Path("requirements-ci.txt").read_text(encoding="utf-8")
    assert "fastapi==0.115.6" in requirements
