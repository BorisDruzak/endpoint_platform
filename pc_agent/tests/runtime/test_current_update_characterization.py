"""Executable baseline for the accepted ALT update and rollback runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pc_agent import endpoint_gateway
from pc_agent.gateway_update_runtime import GatewayUpdateRuntime
from pc_agent.launcher import launcher_main
from pc_agent.update_adapter import EndpointRecommendation, RecommendationResult


_OPERATION_ID = "caa31a48-bf2f-4c1c-8b77-d1be77e12b4e"
_SHA256 = hashlib.sha256(b"verified ALT artifact").hexdigest()


def _recommendation(*, artifact_url: str = "https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/candidate.tar.gz") -> EndpointRecommendation:
    return EndpointRecommendation(
        operation_id=_OPERATION_ID,
        version="3.1.77-rc.1",
        platform="linux_amd64",
        channel="canary",
        artifact_url=artifact_url,
        artifact_name="candidate.tar.gz",
        archive_type="tar.gz",
        sha256=_SHA256,
        size=len(b"verified ALT artifact"),
        reason="scheduled_rollout",
    )


class _ArtifactResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self.content = self
        self._body = body

    async def __aenter__(self) -> _ArtifactResponse:
        return self

    async def __aexit__(self, *_args: object) -> bool:
        return False

    async def iter_chunked(self, _size: int):
        yield self._body

    def raise_for_status(self) -> None:
        return None


class _ArtifactSession:
    def __init__(self, body: bytes) -> None:
        self._response = _ArtifactResponse(body)
        self.requests: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> _ArtifactResponse:
        self.requests.append((url, kwargs))
        return self._response


@pytest.mark.asyncio
async def test_gateway_download_accepts_only_endpoint_artifacts_with_matching_digest_and_size(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A redirected origin or integrity mismatch must never leave a staged artifact."""
    session = _ArtifactSession(b"verified ALT artifact")
    destination = tmp_path / "updates" / "candidate.tar.gz"
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")

    digest, size = await endpoint_gateway._download_gateway_artifact(
        session, _recommendation(), destination
    )

    assert (digest, size) == (_SHA256, len(b"verified ALT artifact"))
    assert destination.read_bytes() == b"verified ALT artifact"
    assert session.requests == [
        (
            "https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/candidate.tar.gz",
            {"headers": {"Authorization": "Bearer device-token"}},
        )
    ]

    with pytest.raises(ValueError, match="Endpoint origin"):
        await endpoint_gateway._download_gateway_artifact(
            session,
            _recommendation(artifact_url="https://downloads.example.test/candidate.tar.gz"),
            tmp_path / "outside-origin.tar.gz",
        )
    assert len(session.requests) == 1

    with pytest.raises(ValueError, match="integrity mismatch"):
        await endpoint_gateway._download_gateway_artifact(
            session,
            EndpointRecommendation(**{**_recommendation().__dict__, "size": 1}),
            tmp_path / "wrong-size.tar.gz",
        )
    assert not (tmp_path / ".wrong-size.tar.gz.tmp").exists()
    assert not (tmp_path / "wrong-size.tar.gz").exists()


def test_gateway_reads_only_a_strict_immutable_alt_selector(tmp_path: Path) -> None:
    """A legacy selector shape cannot supply the active ALT release version."""
    selector = tmp_path / "current.json"
    selector.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.76",
            }
        ),
        encoding="utf-8",
    )

    assert endpoint_gateway.read_gateway_current_version(selector) == "3.1.76"

    selector.write_text(json.dumps({"version": "3.1.76", "previous": "3.1.75"}), encoding="utf-8")
    with pytest.raises(ValueError, match="ALT release selector"):
        endpoint_gateway.read_gateway_current_version(selector)


class _UpdateAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def fetch_recommendation(self, *, platform: str, channel: str) -> RecommendationResult:
        self.calls.append((platform, channel))
        return RecommendationResult("endpoint", _recommendation(), False, None)

    async def acknowledge(self, operation_id: str, status: str) -> bool:
        self.calls.append((operation_id, status))
        return True

    async def record_scheduled_handoff(
        self, operation_id: str, *, assigned_version: str, rollback_version: str
    ) -> bool:
        self.calls.append((operation_id, f"scheduled:{assigned_version}:{rollback_version}"))
        return True

    async def retry_scheduled_acknowledgement(self, operation_id: str) -> bool:
        self.calls.append((operation_id, "scheduled_retry"))
        return True

    async def report_terminal(
        self, operation_id: str, *, status: str, reported_version: str, safe_code: str
    ) -> bool:
        self.calls.append((operation_id, f"{status}:{reported_version}:{safe_code}"))
        return True


@pytest.mark.asyncio
async def test_gateway_stages_an_atomic_pending_update(
    tmp_path: Path,
) -> None:
    """A controlled update exit is permitted only after durable pending state exists."""
    adapter = _UpdateAdapter()

    async def download(item: EndpointRecommendation, destination: Path) -> tuple[str, int]:
        destination.write_bytes(b"verified ALT artifact")
        return item.sha256, item.size

    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.76",
        download=download,
    )

    assert (await runtime.run_once()).status == "scheduled"
    pending_path = tmp_path / "updates" / "pending_alt_update.json"
    assert json.loads(pending_path.read_text(encoding="utf-8")) == {
        "archive_type": "tar.gz",
        "artifact_path": str(
            tmp_path
            / "updates"
            / "downloads"
            / "build-3.1.77-rc.1-caa31a48-bf2f-4c1c-8b77-d1be77e12b4e.tar.gz"
        ),
        "channel": "canary",
        "operation_id": _OPERATION_ID,
        "requested_by": "gateway",
        "requested_reason": "scheduled_rollout",
        "sha256": _SHA256,
        "size": len(b"verified ALT artifact"),
        "target": "linux_amd64",
        "version": "3.1.77-rc.1",
    }
    assert not (pending_path.parent / ".pending_alt_update.json.tmp").exists()

    assert adapter.calls == [
        ("linux_amd64", "canary"),
        (_OPERATION_ID, "requested"),
        (_OPERATION_ID, "scheduled:3.1.77-rc.1:3.1.76"),
    ]


@pytest.mark.asyncio
async def test_gateway_reports_startup_outcome_after_retrying_scheduled_ack(
    tmp_path: Path,
) -> None:
    """An applied update is reported only after restart-derived local history exists."""
    adapter = _UpdateAdapter()
    (tmp_path / "updates").mkdir(parents=True)
    (tmp_path / "updates" / "update_history.json").write_text(
        json.dumps(
            [{"operation_id": _OPERATION_ID, "success": True, "version": "3.1.77-rc.1"}]
        ),
        encoding="utf-8",
    )
    runtime = GatewayUpdateRuntime(
        adapter=adapter,
        data_root=tmp_path,
        current_version="3.1.77-rc.1",
        download=lambda *_args: pytest.fail("startup reporting must not download"),
    )
    assert await runtime.report_startup_outcome() is True
    assert adapter.calls == [
        (_OPERATION_ID, "scheduled_retry"),
        (_OPERATION_ID, "applied:3.1.77-rc.1:post_restart_handshake_confirmed"),
    ]


def test_alt_root_worker_uses_the_durable_pending_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The unprivileged ALT agent delegates publication to the root update worker."""
    monkeypatch.setenv("ENDPOINT_AGENT_ALT_UPDATE_MODE", "1")
    pending_path = tmp_path / "data" / "updates" / "pending_alt_update.json"
    pending_path.parent.mkdir(parents=True)
    pending_path.write_text("{}", encoding="utf-8")
    selected_pending, _installer = launcher_main.select_update_installation(
        data_root=tmp_path / "data"
    )
    assert selected_pending == pending_path
    assert launcher_main.pending_update_requires_privileged_worker(data_root=tmp_path / "data") is True


def test_alt_rollback_can_select_an_existing_immutable_release(
    tmp_path: Path,
) -> None:
    """Rollback must restore an already-verified release with its source revision."""
    install_root = tmp_path / "install"
    manifest_path = install_root / "versions" / "3.1.76" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {"schema_version": 1, "source_revision": "deadbeef", "version": "3.1.76", "files": []}
        ),
        encoding="utf-8",
    )
    current_path = install_root / "current.json"
    current_path.write_text(
        json.dumps(
            {"schema_version": 1, "source_revision": "feedface", "version": "3.1.77-rc.1"}
        ),
        encoding="utf-8",
    )

    launcher_main.rollback_alt_current_version(
        current_path, crashed_version="3.1.77-rc.1", fallback_version="3.1.76"
    )

    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }
