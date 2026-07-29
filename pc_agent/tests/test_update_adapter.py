from __future__ import annotations

from collections.abc import Callable

import pytest

from pc_agent.update_adapter import EndpointUpdateAdapter


class _Response:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self._body = body

    async def __aenter__(self) -> _Response:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def text(self) -> str:
        return self._body


class _Session:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, *, headers: dict[str, str]) -> _Response:
        self.requests.append((url, headers))
        return self.response


def _valid_payload() -> str:
    return """{
        "schema_version": "agent_update_recommendation_v1",
        "operation_id": "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        "build_identifier": "agent-1.2.3",
        "version": "1.2.3",
        "platform": "windows_amd64",
        "channel": "stable",
        "artifact_url": "https://updates.example.test/agent-1.2.3.zip",
        "artifact_name": "agent-1.2.3.zip",
        "archive_type": "zip",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size": 123,
        "reason": "scheduled_rollout"
    }"""


def _adapter(
    response: _Response,
    *,
    legacy_fetch: Callable[[], object] | None = None,
) -> tuple[EndpointUpdateAdapter, _Session]:
    session = _Session(response)
    return (
        EndpointUpdateAdapter(
            api_url="https://endpoint.example.test/",
            bearer_token=lambda: "device-bearer",
            session=session,
            legacy_fetch=legacy_fetch,
        ),
        session,
    )


@pytest.mark.asyncio
async def test_fetch_recommendation_maps_a_valid_primary_assignment() -> None:
    adapter, session = _adapter(_Response(200, _valid_payload()))

    result = await adapter.fetch_recommendation(
        platform="windows_amd64", channel="stable"
    )

    assert result.source == "endpoint"
    assert result.unavailable is False
    assert result.safe_error is None
    assert result.recommendation is not None
    assert result.recommendation.operation_id == "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    assert result.recommendation.version == "1.2.3"
    assert session.requests == [
        (
            "https://endpoint.example.test/agent/v1/updates/recommendation?platform=windows_amd64&channel=stable",
            {"Authorization": "Bearer device-bearer"},
        )
    ]


@pytest.mark.asyncio
async def test_fetch_recommendation_treats_204_as_final_without_legacy_fallback() -> (
    None
):
    legacy_called = False

    async def legacy_fetch() -> object:
        nonlocal legacy_called
        legacy_called = True
        return object()

    adapter, _ = _adapter(_Response(204, ""), legacy_fetch=legacy_fetch)

    result = await adapter.fetch_recommendation(
        platform="linux_amd64", channel="canary"
    )

    assert result.source == "endpoint"
    assert result.recommendation is None
    assert result.unavailable is False
    assert result.safe_error is None
    assert legacy_called is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        _valid_payload().replace("agent_update_recommendation_v1", "unknown_schema"),
        _valid_payload().replace(
            "https://updates.example.test/agent-1.2.3.zip",
            "https://updates.example.test/agent-1.2.3.zip?credential=forbidden",
        ),
    ],
)
async def test_fetch_recommendation_rejects_malformed_primary_contract(
    body: str, tmp_path
) -> None:
    adapter, _ = _adapter(_Response(200, body))

    result = await adapter.fetch_recommendation(
        platform="windows_amd64", channel="stable"
    )

    assert result.source == "endpoint"
    assert result.recommendation is None
    assert result.unavailable is False
    assert result.safe_error == "endpoint_contract_invalid"
    assert not list(tmp_path.rglob("pending_update.json"))
