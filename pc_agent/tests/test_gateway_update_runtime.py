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

    def prepare_scheduled_handoff(
        self, operation_id: str, *, assigned_version: str, rollback_version: str
    ) -> bool:
        self.acknowledgements.append((operation_id, "prepared"))
        return True

    async def retry_scheduled_acknowledgement(self, operation_id: str) -> bool:
        self.acknowledgements.append((operation_id, "scheduled_retry"))
        return True

    async def report_terminal(
        self,
        operation_id: str,
        *,
        status: str,
        reported_version: str,
        safe_code: str,
    ) -> bool:
        self.acknowledgements.append(
            (operation_id, f"{status}:{reported_version}:{safe_code}")
        )
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
    updates = tmp_path / "updates"
    updates.mkdir()
    # A new assignment may target the same version after a failed attempt.
    (updates / "update_history.json").write_text(json.dumps([{
        "operation_id": "33333333-3333-4333-8333-333333333333",
        "success": False,
        "version": _recommendation().version,
    }]), encoding="utf-8")
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
        (_OPERATION_ID, "prepared"),
        (_OPERATION_ID, "scheduled_retry"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("evidence", ["history", "outbox", "during_download"])
async def test_terminal_operation_is_not_scheduled_twice(tmp_path: Path, evidence: str) -> None:
    item = _recommendation()
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", item, False, None))
    updates = tmp_path / "updates"
    updates.mkdir()
    history_path = updates / "update_history.json"
    history = json.dumps([{"operation_id": item.operation_id, "success": False, "version": item.version}])
    if evidence == "history":
        history_path.write_text(history, encoding="utf-8")
    elif evidence == "outbox":
        report = {
            "operation_id": item.operation_id,
            "status": "failed",
            "reported_version": item.version,
            "safe_code": "launcher_apply_failed",
            "report_key": "a" * 32,
            "delivered_at": None,
        }
        (updates / "endpoint_update_reports.json").write_text(json.dumps([report]), encoding="utf-8")

    async def download(recommendation: EndpointRecommendation, destination: Path) -> tuple[str, int]:
        assert evidence == "during_download"
        destination.write_bytes(b"verified-data")
        history_path.write_text(history, encoding="utf-8")
        return recommendation.sha256, recommendation.size

    result = await GatewayUpdateRuntime(
        adapter=adapter, data_root=tmp_path, current_version="3.1.76", download=download,
    ).run_once()

    assert result.status == "idle"
    assert not (updates / "pending_alt_update.json").exists()
    expected_acks = [(item.operation_id, "requested")] if evidence == "during_download" else []
    assert adapter.acknowledgements == expected_acks


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


@pytest.mark.asyncio
async def test_authenticated_rollback_recommendation_allows_an_older_release(
    tmp_path: Path,
) -> None:
    recommendation = _recommendation(version="3.1.79")
    recommendation = EndpointRecommendation(
        **{**recommendation.__dict__, "reason": "rollback of 11111111-1111-4111-8111-111111111111; test recovery"}
    )
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", recommendation, False, None))

    async def download(item: EndpointRecommendation, destination: Path) -> tuple[str, int]:
        destination.write_bytes(b"verified-data")
        return item.sha256, item.size

    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.80",
        download=download,
    )

    assert (await runtime.run_once()).status == "scheduled"
    assert adapter.acknowledgements == [
        (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "prepared"),
        (_OPERATION_ID, "scheduled_retry"),
    ]


@pytest.mark.asyncio
async def test_startup_reports_applied_only_after_retrying_durable_scheduled_ack(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", None, False, None))
    updates = tmp_path / "updates"
    updates.mkdir()
    (updates / "update_history.json").write_text(
        json.dumps(
            [
                {
                    "operation_id": _OPERATION_ID,
                    "previous_version": "3.1.76",
                    "success": True,
                    "version": "3.1.77-rc.1",
                }
            ]
        ),
        encoding="utf-8",
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.77-rc.1",
        download=lambda *_: pytest.fail("startup reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True

    assert adapter.acknowledgements == [
        (_OPERATION_ID, "scheduled_retry"),
        (_OPERATION_ID, "applied:3.1.77-rc.1:post_restart_handshake_confirmed"),
    ]


@pytest.mark.asyncio
async def test_startup_prefers_current_success_over_an_older_failed_operation(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", None, False, None))
    updates = tmp_path / "updates"
    updates.mkdir()
    older_operation = "33333333-3333-4333-8333-333333333333"
    (updates / "update_history.json").write_text(
        json.dumps(
            [
                {
                    "operation_id": older_operation,
                    "success": False,
                    "version": "3.1.78",
                },
                {
                    "operation_id": _OPERATION_ID,
                    "previous_version": "3.1.78",
                    "success": True,
                    "version": "3.1.79",
                },
            ]
        ),
        encoding="utf-8",
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.79",
        download=lambda *_: pytest.fail("startup reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True

    assert adapter.acknowledgements == [
        (_OPERATION_ID, "scheduled_retry"),
        (_OPERATION_ID, "applied:3.1.79:post_restart_handshake_confirmed"),
    ]


@pytest.mark.asyncio
async def test_startup_reports_a_newer_failed_rollback_over_prior_current_success(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", None, False, None))
    updates = tmp_path / "updates"
    updates.mkdir()
    failed_operation = "33333333-3333-4333-8333-333333333333"
    (updates / "update_history.json").write_text(
        json.dumps(
            [
                {
                    "operation_id": _OPERATION_ID,
                    "previous_version": "3.1.80",
                    "success": True,
                    "version": "3.1.81",
                },
                {
                    "operation_id": failed_operation,
                    "success": False,
                    "version": "3.1.80",
                },
            ]
        ),
        encoding="utf-8",
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.81",
        download=lambda *_: pytest.fail("startup reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True

    assert adapter.acknowledgements == [
        (failed_operation, "scheduled_retry"),
        (failed_operation, "failed:3.1.80:launcher_apply_failed"),
    ]


@pytest.mark.asyncio
async def test_startup_reports_rolled_back_release_from_launcher_marker(
    tmp_path: Path,
) -> None:
    adapter = _RecommendationAdapter(RecommendationResult("endpoint", None, False, None))
    updates = tmp_path / "updates"
    updates.mkdir()
    (updates / "update_history.json").write_text(
        json.dumps(
            [
                {
                    "operation_id": _OPERATION_ID,
                    "previous_version": "3.1.76",
                    "success": True,
                    "version": "3.1.77-rc.1",
                }
            ]
        ),
        encoding="utf-8",
    )
    (updates / "last_failed_launch.json").write_text(
        json.dumps(
            {
                "crashed_version": "3.1.77-rc.1",
                "reason": "startup_crash_rollback",
                "rollback_version": "3.1.76",
            }
        ),
        encoding="utf-8",
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.76",
        download=lambda *_: pytest.fail("startup reporting must not download"),
    )

    assert await runtime.report_startup_outcome() is True

    assert adapter.acknowledgements == [
        (_OPERATION_ID, "scheduled_retry"),
        (_OPERATION_ID, "rolled_back:3.1.76:launcher_rolled_back"),
    ]


@pytest.mark.parametrize('success,version,status,code', [
    (False,'3.1.78','failed','launcher_apply_failed'),
    (True,'3.1.76','applied','post_restart_handshake_confirmed'),
])
def test_older_rollback_marker_cannot_hide_a_later_operation(success,version,status,code):
    from pc_agent.gateway_update_runtime import _startup_outcome
    later='33333333-3333-4333-8333-333333333333'
    result=_startup_outcome(history=[
        {'operation_id':_OPERATION_ID,'version':'3.1.77','success':True},
        {'version':'3.1.77','success':False,'reason':'startup_crash_rollback'},
        {'operation_id':later,'version':version,'success':success},
    ],current_version='3.1.76',failed_marker={
        'crashed_version':'3.1.77','rollback_version':'3.1.76',
        'reason':'startup_crash_rollback',
    })
    assert result==(later,status,version,code)


@pytest.mark.asyncio
async def test_alt_pending_stays_hidden_if_durable_handoff_cannot_be_written(tmp_path):
    pending = tmp_path / "updates" / "pending_alt_update.json"

    class Adapter(_RecommendationAdapter):
        def prepare_scheduled_handoff(self, *_args, **_kwargs):
            assert not pending.exists()
            return False

        async def record_scheduled_handoff(self, *_args, **_kwargs):
            assert not pending.exists(), "root watcher can observe a request without its journal"
            return False

    adapter = Adapter(RecommendationResult("endpoint", _recommendation(), False, None))

    async def download(item, destination):
        destination.write_bytes(b"verified-data")
        return item.sha256, item.size

    runtime = GatewayUpdateRuntime(
        adapter=adapter, data_root=tmp_path, current_version="3.1.76", download=download,
    )
    assert (await runtime.run_once()).status == "handoff_pending"
    assert not pending.exists()


@pytest.mark.parametrize("interruption", ["before_rename", "after_rename"])
@pytest.mark.asyncio
async def test_alt_handoff_recovers_after_interruption_at_pending_rename(
    tmp_path, monkeypatch, interruption,
):
    from pc_agent.platform.windows import durable_state
    from pc_agent.update_adapter import EndpointUpdateAdapter, load_endpoint_update_handoffs

    pending = tmp_path / "updates" / "pending_alt_update.json"
    operation = _recommendation()

    class Interrupted(BaseException):
        pass

    class Adapter(EndpointUpdateAdapter):
        async def fetch_recommendation(self, **kwargs):
            return RecommendationResult("endpoint", operation, False, None)

        async def acknowledge(self, operation_id, status):
            return True

        async def report_terminal(self, operation_id, **kwargs):
            assert operation_id == _OPERATION_ID
            assert kwargs["status"] == "applied"
            return True

    def runtime(version):
        return GatewayUpdateRuntime(
            adapter=Adapter(
                api_url="https://endpoint.example.test", bearer_token=lambda: "test",
                session=None, data_root=tmp_path,
            ),
            data_root=tmp_path, current_version=version, download=download,
        )

    async def download(item, destination):
        destination.write_bytes(b"verified-data")
        return item.sha256, item.size

    original_replace = durable_state.os.replace

    def intercept(source, destination):
        if Path(destination) != pending:
            return original_replace(source, destination)
        existing = load_endpoint_update_handoffs(tmp_path)
        assert existing == [{
            "operation_id": _OPERATION_ID, "assigned_version": operation.version,
            "rollback_version": "3.1.76", "scheduled_ack_delivered_at": None,
        }]
        if interruption == "after_rename":
            original_replace(source, destination)
        raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(durable_state.os, "replace", intercept)
        with pytest.raises(Interrupted):
            await runtime("3.1.76").run_once()

    if interruption == "before_rename":
        assert not pending.exists()
        assert (await runtime("3.1.76").run_once()).status == "scheduled"
    assert json.loads(pending.read_text())["operation_id"] == _OPERATION_ID
    (pending.parent / "update_history.json").write_text(json.dumps([{
        "operation_id": _OPERATION_ID, "version": operation.version,
        "previous_version": "3.1.76", "success": True,
    }]))
    pending.unlink()
    assert await runtime(operation.version).report_startup_outcome()
