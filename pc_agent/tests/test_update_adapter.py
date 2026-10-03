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

    def get(self, url: str, *, headers: dict[str, str], allow_redirects: bool = False) -> _Response:
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


@pytest.mark.asyncio
async def test_legacy_canary_query_accepts_server_assigned_stable_channel() -> None:
    adapter, _ = _adapter(_Response(200, _valid_payload()))
    result = await adapter.fetch_recommendation(platform="windows_amd64", channel="canary")
    assert result.safe_error is None
    assert result.recommendation is not None
    assert result.recommendation.channel == "stable"


@pytest.mark.asyncio
@pytest.mark.parametrize("corrupt", ["{", "{}", '[{"operation_id":"lost"}]'])
@pytest.mark.parametrize("journal", ["reports", "handoffs"])
async def test_strict_recovery_refuses_discovery_with_corrupt_report_journal(tmp_path, corrupt, journal):
    session = _Session(_Response(204, ""))
    adapter = EndpointUpdateAdapter(api_url="https://endpoint.example.test",
        bearer_token=lambda: "device-bearer", session=session,
        strict_recovery=True, data_root=tmp_path)
    path = adapter._report_journal_path() if journal == "reports" else adapter._update_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(corrupt)
    with pytest.raises(ValueError, match="journal"):
        await adapter.fetch_recommendation(platform="windows_amd64", channel="canary")
    assert session.requests == []


@pytest.mark.parametrize("field,value", [
    ("operation_id", "bad-id"), ("report_key", "bad-key"),
    ("status", "scheduled"), ("reported_version", "bad-version"),
    ("safe_code", "launcher_rolled_back"), ("delivered_at", "CORRUPT"),
    ("delivered_at", "2026-10-02T10:00:00"), ("status", None),
])
def test_strict_report_journal_rejects_semantic_corruption(tmp_path, field, value):
    record = dict(operation_id="caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        report_key="a" * 32, status="failed", reported_version="3.2.79",
        safe_code="launcher_apply_failed", delivered_at=None)
    record[field] = value
    path = tmp_path / "updates" / "endpoint_update_reports.json"
    path.parent.mkdir()
    path.write_text(json.dumps([record]))
    with pytest.raises(ValueError, match="journal"):
        EndpointUpdateAdapter(api_url="https://endpoint.example.test",
            bearer_token=lambda: "token", session=_Session(_Response(204, "")),
            data_root=tmp_path, strict_recovery=True)


@pytest.mark.parametrize("journal", ["reports", "handoffs"])
def test_strict_journals_reject_duplicate_records(tmp_path, journal):
    record = dict(operation_id="caa31a48-bf2f-4f1c-8b77-d1be77e12b4e",
        assigned_version="3.2.80", rollback_version="3.2.79",
        scheduled_ack_delivered_at=None)
    if journal == "reports":
        record = dict(operation_id=record["operation_id"], report_key="a" * 32,
            status="failed", reported_version="3.2.79", safe_code="launcher_apply_failed",
            delivered_at=None)
    path = tmp_path / "updates" / ("endpoint_update_reports.json" if journal == "reports"
        else "endpoint_update_state.json")
    path.parent.mkdir()
    path.write_text(json.dumps([record, record]))
    with pytest.raises(ValueError, match="journal"):
        EndpointUpdateAdapter(api_url="https://endpoint.example.test",
            bearer_token=lambda: "token", session=_Session(_Response(204, "")),
            data_root=tmp_path, strict_recovery=True)


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
    body: str,
) -> None:
    adapter, _ = _adapter(_Response(200, body))

    result = await adapter.fetch_recommendation(
        platform="windows_amd64", channel="stable"
    )

    assert result.source == "endpoint"
    assert result.recommendation is None
    assert result.unavailable is False
    assert result.safe_error == "endpoint_contract_invalid"


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
async def test_primary_200_payload_error_fails_closed_without_legacy() -> None:
    calls = 0

    class Broken(_Response):
        async def text(self) -> str:
            raise aiohttp.ClientPayloadError("truncated response")

    async def legacy_fetch() -> object:
        nonlocal calls
        calls += 1
        return {}

    adapter, _ = _adapter(Broken(200, ""), legacy_fetch=legacy_fetch)

    result = await adapter.fetch_recommendation(
        platform="windows_amd64", channel="stable"
    )

    assert result.source == "endpoint"
    assert result.recommendation is None
    assert result.safe_error == "endpoint_unavailable"
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


@pytest.mark.asyncio
async def test_scheduled_handoff_ack_is_durable_across_adapter_restart(
    tmp_path,
) -> None:
    class Session:
        def __init__(self, status: int):
            self.status = status
            self.bodies: list[dict[str, object]] = []

        def post(self, url: str, *, headers: dict[str, str], json: dict[str, object]):
            self.bodies.append(json)
            return _Response(self.status, "")

    first_session = Session(500)
    first = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=first_session,
        data_root=tmp_path,
    )
    operation_id = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"

    assert (
        await first.record_scheduled_handoff(
            operation_id,
            assigned_version="2.0.0",
            rollback_version="1.9.0",
        )
        is False
    )

    second_session = Session(204)
    second = EndpointUpdateAdapter(
        api_url="https://endpoint.example.test",
        bearer_token=lambda: "token",
        session=second_session,
        data_root=tmp_path,
    )
    assert await second.retry_scheduled_acknowledgement(operation_id) is True
    assert first_session.bodies == [
        {"schema_version": "agent_update_ack_v1", "status": "scheduled"}
    ]
    assert second_session.bodies == first_session.bodies

    state = json.loads(
        (tmp_path / "updates" / "endpoint_update_state.json").read_text(
            encoding="utf-8"
        )
    )
    assert state == [
        {
            "operation_id": operation_id,
            "assigned_version": "2.0.0",
            "rollback_version": "1.9.0",
            "scheduled_ack_delivered_at": state[0]["scheduled_ack_delivered_at"],
        }
    ]
    assert isinstance(state[0]["scheduled_ack_delivered_at"], str)


@pytest.mark.asyncio
@pytest.mark.parametrize("journal", ["endpoint_update_state.json", "endpoint_update_reports.json"])
@pytest.mark.parametrize("failure", ["file_flush", "replace", "directory_flush"])
async def test_journal_failure_blocks_network_until_durable_restart(tmp_path, monkeypatch, journal, failure):
    from pc_agent.platform.windows import durable_state
    class Session:
        def __init__(self):
            self.bodies = []
        def post(self, url, *, headers, json):
            self.bodies.append(json)
            return _Response(200 if url.endswith("reports") else 204, "")
    session = Session()
    def adapter():
        return EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=session, data_root=tmp_path)
    operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    async def perform(owner):
        if journal == "endpoint_update_state.json":
            return await owner.record_scheduled_handoff(operation, assigned_version="3.2.2", rollback_version="3.2.1")
        return await owner.report_terminal(operation, status="rolled_back", reported_version="3.2.1", safe_code="launcher_rolled_back")
    original_flush = durable_state.flush_directory
    def fault(*args, **kwargs):
        if failure == "directory_flush" and args[0] != tmp_path / "updates":
            return original_flush(*args, **kwargs)
        raise OSError("injected")
    with monkeypatch.context() as patch:
        target, attribute = (durable_state, "flush_directory") if failure == "directory_flush" else (durable_state.os, "fsync" if failure == "file_flush" else "replace")
        patch.setattr(target, attribute, fault)
        with pytest.raises(OSError, match="injected"):
            await perform(adapter())
    assert session.bodies == []
    path = tmp_path / "updates" / journal
    persisted = json.loads(path.read_text()) if path.exists() else []
    key = persisted[0]["report_key"] if persisted and journal.endswith("reports.json") else None
    assert await perform(adapter())
    if key is not None:
        assert session.bodies[0]["report_key"] == key
    assert len(json.loads(path.read_text())) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("journal", ["endpoint_update_state.json", "endpoint_update_reports.json"])
async def test_delivered_journal_retry_finishes_failed_directory_flush(tmp_path, monkeypatch, journal):
    from pc_agent.platform.windows import durable_state
    class Session:
        def __init__(self):
            self.bodies = []
        def post(self, url, *, headers, json):
            self.bodies.append(json)
            return _Response(200 if url.endswith("reports") else 204, "")
    session = Session()
    def adapter():
        return EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=session, data_root=tmp_path)
    operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    async def perform(owner):
        if journal == "endpoint_update_state.json":
            return await owner.record_scheduled_handoff(operation, assigned_version="3.2.2", rollback_version="3.2.1")
        return await owner.report_terminal(operation, status="rolled_back", reported_version="3.2.1", safe_code="launcher_rolled_back")
    original = durable_state.flush_directory
    calls = []
    def flush(path):
        calls.append(path)
        if session.bodies and path == tmp_path / "updates":
            raise OSError("delivered metadata failure")
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", flush)
        with pytest.raises(OSError, match="delivered metadata"):
            await perform(adapter())
    assert len(session.bodies) == 1
    calls.clear()
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", lambda path: calls.append(path))
        assert await perform(adapter())
    assert calls == [tmp_path / "updates"]
    assert len(session.bodies) == 1


@pytest.mark.asyncio
async def test_scheduled_ack_merges_operations_created_while_network_ack_waits(tmp_path):
    import asyncio
    first_operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    second_operation = "daa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    entered, release = asyncio.Event(), asyncio.Event()
    owner = EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=object(), data_root=tmp_path)
    async def ack(operation, status):
        if operation == first_operation:
            entered.set()
            await release.wait()
        return True
    owner.acknowledge = ack
    first = asyncio.create_task(owner.record_scheduled_handoff(first_operation, assigned_version="3.2.2", rollback_version="3.2.1"))
    await entered.wait()
    assert await owner.record_scheduled_handoff(second_operation, assigned_version="3.2.3", rollback_version="3.2.1")
    release.set()
    assert await first
    records = json.loads((tmp_path / "updates" / "endpoint_update_state.json").read_text())
    assert {item["operation_id"] for item in records} == {first_operation, second_operation}
    assert all(item["scheduled_ack_delivered_at"] is not None for item in records)


@pytest.mark.asyncio
@pytest.mark.parametrize("same_operation", [False, True])
async def test_concurrent_terminal_reports_merge_and_reuse_operation_report_key(tmp_path, same_operation):
    import asyncio
    entered, release = asyncio.Event(), asyncio.Event()
    first_operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    second_operation = first_operation if same_operation else "daa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    class Response(_Response):
        async def __aenter__(self):
            entered.set()
            await release.wait()
            return self
    class Session:
        def __init__(self):
            self.bodies = []
        def post(self, url, *, headers, json):
            self.bodies.append(json)
            return Response(200, "") if len(self.bodies) == 1 else _Response(200, "")
    session = Session()
    owner = EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=session, data_root=tmp_path)
    async def report(operation):
        return await owner.report_terminal(operation, status="rolled_back", reported_version="3.2.1", safe_code="launcher_rolled_back")
    first = asyncio.create_task(report(first_operation))
    await entered.wait()
    assert await report(second_operation)
    release.set()
    assert await first
    records = json.loads((tmp_path / "updates" / "endpoint_update_reports.json").read_text())
    assert {item["operation_id"] for item in records} == {first_operation, second_operation}
    assert all(item["delivered_at"] is not None for item in records)
    assert len(records) == (1 if same_operation else 2)
    if same_operation:
        assert session.bodies[0]["report_key"] == session.bodies[1]["report_key"]


def test_linux_adapter_branch_preserves_existing_journal_mode(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import stat
    from pc_agent import update_adapter
    from pc_agent.platform.windows import acl
    path = tmp_path / "updates" / "endpoint_update_state.json"
    path.parent.mkdir()
    path.write_text('[]')
    expected_mode = stat.S_IMODE(path.stat().st_mode)
    monkeypatch.setattr(update_adapter, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(acl, "os", SimpleNamespace(name="posix"))
    owner = EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=object(), data_root=tmp_path)
    owner._write_update_state([])
    assert stat.S_IMODE(path.stat().st_mode) == expected_mode
    assert json.loads(path.read_text()) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("journal", ["endpoint_update_state.json", "endpoint_update_reports.json"])
@pytest.mark.parametrize("delivered", [False, True])
async def test_visible_journal_retry_requires_flush_before_any_network(tmp_path, monkeypatch, journal, delivered):
    from pc_agent.platform.windows import durable_state
    events = []
    class Session:
        def post(self, url, *, headers, json):
            events.append("POST")
            return _Response(200 if url.endswith("reports") else 204, "")
    session = Session()
    def owner():
        return EndpointUpdateAdapter(api_url="https://endpoint.example.test", bearer_token=lambda: "test", session=session, data_root=tmp_path)
    operation = "caa31a48-bf2f-4f1c-8b77-d1be77e12b4e"
    async def perform(adapter):
        if journal == "endpoint_update_state.json":
            return await adapter.record_scheduled_handoff(operation, assigned_version="3.2.2", rollback_version="3.2.1")
        return await adapter.report_terminal(operation, status="rolled_back", reported_version="3.2.1", safe_code="launcher_rolled_back")
    original_flush = durable_state.flush_directory
    def fail(path):
        if path == tmp_path / "updates":
            events.append("FLUSH_FAILURE")
            raise OSError("persistent journal metadata failure")
        original_flush(path)
    if delivered:
        assert await perform(owner())
    with monkeypatch.context() as patch:
        patch.setattr(durable_state, "flush_directory", fail)
        if not delivered:
            with pytest.raises(OSError, match="persistent journal"):
                await perform(owner())
        path = tmp_path / "updates" / journal
        assert path.exists()
        visible = json.loads(path.read_text())
        report_key = visible[0].get("report_key")
        for _ in range(2):
            events.clear()
            with pytest.raises(OSError, match="persistent journal"):
                await perform(owner())
            assert events == ["FLUSH_FAILURE"]
    events.clear()
    assert await perform(owner())
    assert events == ([] if delivered else ["POST"])
    if report_key:
        assert json.loads(path.read_text())[0]["report_key"] == report_key

@pytest.mark.skipif(__import__('os').name != 'nt', reason='native Windows journal process race')
@pytest.mark.parametrize('same_operation',[False,True])
def test_real_processes_merge_scheduled_and_terminal_journals(tmp_path,same_operation):
    import subprocess, sys
    from uuid import uuid4
    name = 'Local\\EndpointJournalTest-' + uuid4().hex
    code = '''
import asyncio,json,sys,time
from pathlib import Path
from pc_agent.platform.windows import update_transaction as transaction
from pc_agent.update_adapter import EndpointUpdateAdapter
transaction._MUTEX_NAME=sys.argv[2]
class Response:
    status=200
    async def __aenter__(self): return self
    async def __aexit__(self,*_): pass
class Session:
    def post(self,url,**__):
        response=Response(); response.status=204 if url.endswith('/ack') else 200; return response
a=EndpointUpdateAdapter(api_url='https://example.test',bearer_token=lambda:'test',session=Session(),data_root=Path(sys.argv[1]))
original=a._load_update_state
def slow():
    value=original(); time.sleep(.1); return value
a._load_update_state=slow
async def run():
    for _ in range(100):
        if await a.record_scheduled_handoff(sys.argv[3],assigned_version='3.2.82',rollback_version='3.2.79'): break
        await asyncio.sleep(.02)
    else: raise AssertionError('handoff busy indefinitely')
    for _ in range(100):
        if await a.report_terminal(sys.argv[3],status='failed',reported_version='3.2.79',safe_code='launcher_apply_failed'): break
        await asyncio.sleep(.02)
    else: raise AssertionError('report busy indefinitely')
asyncio.run(run())
'''
    operations=[str(uuid4()) for _ in range(4)]
    if same_operation:operations=[operations[0]]*4
    children=[subprocess.Popen([sys.executable,'-c',code,str(tmp_path),name,op],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for op in operations]
    for child in children:
        out,err=child.communicate(timeout=30)
        assert child.returncode == 0, out+err
    states=json.loads((tmp_path/'updates'/'endpoint_update_state.json').read_text())
    reports=json.loads((tmp_path/'updates'/'endpoint_update_reports.json').read_text())
    assert {r['operation_id'] for r in states} == set(operations)
    assert {r['operation_id'] for r in reports} == set(operations)
    assert len(reports)==len({r['report_key'] for r in reports})==len(set(operations))
    assert all(r['scheduled_ack_delivered_at'] for r in states)
    assert all(r['delivered_at'] for r in reports)

@pytest.mark.asyncio
async def test_contended_transaction_defers_adapter_without_blocking_event_loop(tmp_path):
    import threading
    from pc_agent.platform.windows import update_transaction
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path,tmp_path/'updates'/'pending_update.json')
    acquired=threading.Event();release=threading.Event()
    def hold():
        with update_transaction.update_transaction(paths):
            acquired.set();release.wait(5)
    owner=threading.Thread(target=hold);owner.start();assert acquired.wait(3)
    adapter=EndpointUpdateAdapter(api_url='https://example.test',bearer_token=lambda:'token',session=object(),data_root=tmp_path)
    try:
        assert not await adapter.record_scheduled_handoff('caa31a48-bf2f-4f1c-8b77-d1be77e12b4e',assigned_version='3.2.82',rollback_version='3.2.79')
        assert not release.is_set() and owner.is_alive()
        assert not adapter._update_state_path().exists()
    finally:
        release.set();owner.join(5)
