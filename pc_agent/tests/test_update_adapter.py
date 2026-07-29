from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import aiohttp
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


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 501])
async def test_eligible_primary_failures_call_legacy_once(status: int) -> None:
    calls = 0

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter, _ = _adapter(_Response(status, ""), legacy_fetch=legacy_fetch)
    assert (
        await adapter.fetch_recommendation(platform="windows_amd64", channel="stable")
    ).source == "legacy"
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 409, 422, 500])
async def test_noneligible_primary_failures_never_call_legacy(status: int) -> None:
    calls = 0

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter, _ = _adapter(_Response(status, ""), legacy_fetch=legacy_fetch)
    assert (
        await adapter.fetch_recommendation(platform="windows_amd64", channel="stable")
    ).source == "endpoint"
    assert calls == 0


@pytest.mark.asyncio
async def test_connection_failure_calls_legacy_once() -> None:
    calls = 0

    class Session:
        def get(self, url: str, *, headers: dict[str, str]):
            raise aiohttp.ClientConnectionError()

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=Session(),
        legacy_fetch=legacy_fetch,
    )
    assert (
        await adapter.fetch_recommendation(platform="windows_amd64", channel="stable")
    ).source == "legacy"
    assert calls == 1


@pytest.mark.asyncio
async def test_timeout_before_primary_response_calls_legacy_once() -> None:
    calls = 0

    class Session:
        def get(self, url: str, *, headers: dict[str, str]):
            raise asyncio.TimeoutError()

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=Session(),
        legacy_fetch=legacy_fetch,
    )
    assert (
        await adapter.fetch_recommendation(platform="windows_amd64", channel="stable")
    ).source == "legacy"
    assert calls == 1


@pytest.mark.asyncio
async def test_primary_200_body_transport_failure_never_calls_legacy() -> None:
    calls = 0

    class Broken(_Response):
        async def text(self) -> str:
            raise aiohttp.ClientConnectionError()

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter, _ = _adapter(Broken(200, ""), legacy_fetch=legacy_fetch)
    result = await adapter.fetch_recommendation(
        platform="windows_amd64", channel="stable"
    )
    assert result.source == "endpoint" and result.recommendation is None
    assert calls == 0


@pytest.mark.asyncio
async def test_uppercase_https_wire_form_is_rejected() -> None:
    adapter, _ = _adapter(
        _Response(200, _valid_payload().replace("https://", "HTTPS://"))
    )
    assert (
        await adapter.fetch_recommendation(platform="windows_amd64", channel="stable")
    ).safe_error == "endpoint_contract_invalid"


@pytest.mark.asyncio
async def test_terminal_report_reuses_report_key_after_failed_post(tmp_path) -> None:
    class Session:
        def __init__(self):
            self.bodies = []

        def get(self, url: str, *, headers: dict[str, str]):
            raise AssertionError

        def post(self, url: str, *, headers: dict[str, str], json: dict[str, object]):
            self.bodies.append(json)
            return _Response(500, "")

    first_session, second_session = Session(), Session()
    first = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=first_session,
        data_root=tmp_path,
    )
    second = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=second_session,
        data_root=tmp_path,
    )
    args = ("caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",)
    kwargs = {
        "status": "failed",
        "reported_version": "1.2.3",
        "safe_code": "launcher_apply_failed",
    }
    assert await first.report_terminal(*args, **kwargs) is False
    assert await second.report_terminal(*args, **kwargs) is False
    assert (
        first_session.bodies[0]["report_key"] == second_session.bodies[0]["report_key"]
    )
    record = json.loads(
        (tmp_path / "updates" / "endpoint_update_reports.json").read_text()
    )[0]
    assert set(record) == {
        "operation_id",
        "report_key",
        "status",
        "reported_version",
        "safe_code",
        "delivered_at",
    }
