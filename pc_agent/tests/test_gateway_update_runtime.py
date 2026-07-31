"""Gateway-native ALT update lifecycle contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pc_agent.gateway_update_runtime import GatewayUpdateRuntime
from pc_agent.update_adapter import EndpointRecommendation, RecommendationResult


_OPERATION_ID = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"


class _RecommendationAdapter:
    def __init__(self, result: RecommendationResult) -> None:
        self.result = result
        self.acknowledgements: list[tuple[str, str]] = []

    async def fetch_recommendation(
        self, *, platform: str, channel: str
    ) -> RecommendationResult:
        assert (platform, channel) == ("linux_amd64", "canary")
        return self.result

    async def acknowledge(self, operation_id: str, status: str) -> bool:
        self.acknowledgements.append((operation_id, status))
        return True

    async def record_scheduled_handoff(
        self, operation_id: str, *, assigned_version: str, rollback_version: str
    ) -> bool:
        self.acknowledgements.append((operation_id, "scheduled"))
        return True


def _recommendation(version: str = "3.1.77-rc.1") -> EndpointRecommendation:
    return EndpointRecommendation(
        operation_id=_OPERATION_ID,
        version=version,
        platform="linux_amd64",
        channel="canary",
        artifact_url="https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/build.tar.gz",
        artifact_name="endpoint-agent-alt.tar.gz",
        archive_type="tar.gz",
        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        size=12,
        reason="scheduled_rollout",
    )


@pytest.mark.asyncio
async def test_newer_linux_canary_recommendation_writes_durable_alt_pending_state(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(
        RecommendationResult("endpoint", _recommendation(), False, None)
    )

    async def download(item: EndpointRecommendation, destination: Path) -> tuple[str, int]:
        destination.write_bytes(b"verified-data")
        return item.sha256, item.size

    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.76",
        download=download,
    )

    result = await runtime.run_once()

    assert result.status == "scheduled"
    pending = json.loads(
        (tmp_path / "updates" / "pending_alt_update.json").read_text(encoding="utf-8")
    )
    assert pending == {
        "archive_type": "tar.gz",
        "artifact_path": str(
            tmp_path
            / "updates"
            / "downloads"
            / "build-3.1.77-rc.1-caa31a48-bf2f-4f1c-8b77-d1be77e12b4e.tar.gz"
        ),
        "channel": "canary",
        "operation_id": _OPERATION_ID,
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size": 12,
        "target": "linux_amd64",
        "version": "3.1.77-rc.1",
    }
    assert adapter.acknowledgements == [
        (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "scheduled"),
    ]


@pytest.mark.asyncio
async def test_unavailable_gateway_does_not_create_pending_or_fallback_state(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(
        RecommendationResult("endpoint", None, True, "endpoint_unavailable")
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.76",
        download=lambda *_: pytest.fail("unavailable controller must not download"),
    )

    result = await runtime.run_once()

    assert result.status == "unavailable"
    assert not (tmp_path / "updates" / "pending_alt_update.json").exists()
    assert adapter.acknowledgements == []
