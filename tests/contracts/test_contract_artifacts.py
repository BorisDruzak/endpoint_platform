import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from endpoint_contracts import (
    AgentBuildRecommendationV1,
    AgentCommandAckV1,
    AgentCommandV1,
    AgentHeartbeatV1,
    AgentResultV1,
    AgentSessionV1,
    DeviceIdentityV1,
    EnrollmentRequestV1,
    EnrollmentResponseV1,
)
from tools.contracts.generate_contract_artifacts import render_artifacts


PUBLIC_MODELS = {
    "device-identity-v1.json": DeviceIdentityV1,
    "agent-session-v1.json": AgentSessionV1,
    "enrollment-request-v1.json": EnrollmentRequestV1,
    "enrollment-response-v1.json": EnrollmentResponseV1,
    "agent-command-v1.json": AgentCommandV1,
    "agent-command-ack-v1.json": AgentCommandAckV1,
    "agent-result-v1.json": AgentResultV1,
    "agent-heartbeat-v1.json": AgentHeartbeatV1,
    "agent-build-recommendation-v1.json": AgentBuildRecommendationV1,
}


@pytest.mark.parametrize("filename", PUBLIC_MODELS)
def test_fixture_validates_against_model_and_schema(filename: str) -> None:
    fixture = json.loads(
        (Path("tests/fixtures/contracts") / filename).read_text(encoding="utf-8")
    )
    schema = json.loads(
        (Path("contracts/jsonschema") / filename).read_text(encoding="utf-8")
    )

    PUBLIC_MODELS[filename].model_validate(fixture)
    Draft202012Validator(schema).validate(fixture)


def test_committed_contract_artifacts_match_renderer_without_mutation(tmp_path: Path) -> None:
    rendered = render_artifacts(tmp_path)

    assert not any(tmp_path.iterdir())
    assert rendered
    for relative_path, expected in rendered.items():
        assert (Path.cwd() / relative_path).read_text(encoding="utf-8") == expected


def test_check_exits_nonzero_when_a_tracked_artifact_differs(tmp_path: Path) -> None:
    generated_path = tmp_path / "contracts/jsonschema/device-identity-v1.json"
    generated_path.parent.mkdir(parents=True)
    generated_path.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "tools/contracts/generate_contract_artifacts.py",
            "--check",
            "--output-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "contracts/jsonschema/device-identity-v1.json" in result.stderr


@pytest.mark.parametrize("filename", PUBLIC_MODELS)
def test_fixture_text_has_no_credential_labels_or_absolute_paths(filename: str) -> None:
    fixture_text = (Path("tests/fixtures/contracts") / filename).read_text(
        encoding="utf-8"
    )

    assert not re.search(
        r'"(?:access_)?(?:token|secret|password|credential|api[_-]?key)"\s*:',
        fixture_text,
        re.IGNORECASE,
    )
    assert not re.search(r'"(?:[A-Za-z]:[\\/]|/|\\\\)', fixture_text)
