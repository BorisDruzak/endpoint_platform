"""Executable baseline for the accepted ALT update and rollback runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pc_agent import alt_update_installer, endpoint_gateway, gateway_update_runtime
from pc_agent.gateway_update_runtime import GatewayUpdateRuntime
from pc_agent.launcher import launcher_main
from pc_agent.update_adapter import EndpointRecommendation, RecommendationResult


_OPERATION_ID = "caa31a48-bf2f-4c1c-8b77-d1be77e12b4e"
_SHA256 = hashlib.sha256(b"verified ALT artifact").hexdigest()


def _recommendation(
    *,
    artifact_url: str = "https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/candidate.tar.gz",
) -> EndpointRecommendation:
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
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.status = status
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
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self._response = _ArtifactResponse(body, status=status)
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
            {
                "headers": {"Authorization": "Bearer device-token"},
                "allow_redirects": False,
            },
        )
    ]

    with pytest.raises(ValueError, match="Endpoint origin"):
        await endpoint_gateway._download_gateway_artifact(
            session,
            _recommendation(
                artifact_url="https://downloads.example.test/candidate.tar.gz"
            ),
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


@pytest.mark.asyncio
async def test_gateway_artifact_download_disables_redirects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A controller redirect must not get a chance to send the bearer to another host."""
    session = _ArtifactSession(b"verified ALT artifact")
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")

    await endpoint_gateway._download_gateway_artifact(
        session, _recommendation(), tmp_path / "candidate.tar.gz"
    )

    assert session.requests == [
        (
            "https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/candidate.tar.gz",
            {
                "headers": {"Authorization": "Bearer device-token"},
                "allow_redirects": False,
            },
        )
    ]


@pytest.mark.asyncio
async def test_gateway_artifact_download_rejects_redirect_without_following_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A redirect response is rejected before a second host can receive the bearer."""
    session = _ArtifactSession(b"", status=302)
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")

    with pytest.raises(ValueError, match="unavailable"):
        await endpoint_gateway._download_gateway_artifact(
            session, _recommendation(), tmp_path / "redirected.tar.gz"
        )

    assert session.requests == [
        (
            "https://endpoint.sosnadmin.local/agent/v1/updates/artifacts/candidate.tar.gz",
            {
                "headers": {"Authorization": "Bearer device-token"},
                "allow_redirects": False,
            },
        )
    ]
    assert not (tmp_path / "redirected.tar.gz").exists()


@pytest.mark.asyncio
async def test_gateway_artifact_download_rejects_a_non_https_configured_origin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A configuration regression to HTTP must fail before any artifact request."""
    session = _ArtifactSession(b"verified ALT artifact")
    monkeypatch.setattr(endpoint_gateway, "_ORIGIN", "http://endpoint.sosnadmin.local")
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")

    with pytest.raises(ValueError, match="HTTPS"):
        await endpoint_gateway._download_gateway_artifact(
            session,
            _recommendation(),
            tmp_path / "candidate.tar.gz",
        )

    assert session.requests == []


@pytest.mark.asyncio
async def test_gateway_artifact_download_rejects_sha256_mismatch_even_when_size_matches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An altered artifact with the expected byte count must not be published."""
    session = _ArtifactSession(b"verified ALT artifact")
    monkeypatch.setattr(endpoint_gateway, "_credential", lambda: "device-token")
    recommendation = EndpointRecommendation(
        **{**_recommendation().__dict__, "sha256": "0" * 64}
    )

    with pytest.raises(ValueError, match="integrity mismatch"):
        await endpoint_gateway._download_gateway_artifact(
            session, recommendation, tmp_path / "wrong-sha.tar.gz"
        )

    assert not (tmp_path / "wrong-sha.tar.gz").exists()
    assert not (tmp_path / ".wrong-sha.tar.gz.tmp").exists()


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

    selector.write_text(
        json.dumps({"version": "3.1.76", "previous": "3.1.75"}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="ALT release selector"):
        endpoint_gateway.read_gateway_current_version(selector)


class _UpdateAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def fetch_recommendation(
        self, *, platform: str, channel: str
    ) -> RecommendationResult:
        self.calls.append((platform, channel))
        return RecommendationResult("endpoint", _recommendation(), False, None)

    async def acknowledge(self, operation_id: str, status: str) -> bool:
        self.calls.append((operation_id, status))
        return True

    async def record_scheduled_handoff(
        self, operation_id: str, *, assigned_version: str, rollback_version: str
    ) -> bool:
        self.calls.append(
            (operation_id, f"scheduled:{assigned_version}:{rollback_version}")
        )
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
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A controlled update exit is permitted only after durable pending state exists."""
    adapter = _UpdateAdapter()
    replace_events: list[tuple[str, str, bool, bool, dict[str, object]]] = []
    original_replace = Path.replace

    def observe_pending_replace(source: Path, target: Path) -> Path:
        if source.name == ".pending_alt_update.json.tmp":
            replace_events.append(
                (
                    source.name,
                    target.name,
                    source.exists(),
                    target.exists(),
                    json.loads(source.read_text(encoding="utf-8")),
                )
            )
        return original_replace(source, target)

    monkeypatch.setattr(gateway_update_runtime.Path, "replace", observe_pending_replace)

    async def download(
        item: EndpointRecommendation, destination: Path
    ) -> tuple[str, int]:
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
    assert replace_events == [
        (
            ".pending_alt_update.json.tmp",
            "pending_alt_update.json",
            True,
            False,
            json.loads(pending_path.read_text(encoding="utf-8")),
        )
    ]

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
    assert (
        launcher_main.pending_update_requires_privileged_worker(
            data_root=tmp_path / "data"
        )
        is True
    )


def test_alt_rollback_can_select_an_existing_immutable_release(
    tmp_path: Path,
) -> None:
    """Only the root worker may restore the previous manifest-verified release."""
    install_root = tmp_path / "install"
    release = install_root / "versions" / "3.1.76"
    binary = release / "endpoint-agent" / "endpoint-agent"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"accepted")
    binary.chmod(0o755)
    manifest_path = release / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "deadbeef",
                "version": "3.1.76",
                "files": [
                    {
                        "path": "endpoint-agent/endpoint-agent",
                        "sha256": hashlib.sha256(b"accepted").hexdigest(),
                        "mode": "0755",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    current_path = install_root / "current.json"
    current_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "feedface",
                "version": "3.1.77-rc.1",
            }
        ),
        encoding="utf-8",
    )
    (install_root / "previous.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_revision": "deadbeef",
                "version": "3.1.76",
            }
        ),
        encoding="utf-8",
    )
    data_root = tmp_path / "data"
    request = data_root / "updates" / "rollback-request.json"
    request.parent.mkdir(parents=True)
    request.write_text(
        json.dumps(
            {
                "crashed_source_revision": "feedface",
                "crashed_version": "3.1.77-rc.1",
                "rollback_source_revision": "deadbeef",
                "rollback_version": "3.1.76",
                "schema_version": "endpoint_alt_rollback_request_v1",
            }
        ),
        encoding="utf-8",
    )
    request.chmod(0o600)

    assert alt_update_installer.apply_alt_rollback(install_root, data_root) == (
        True,
        "3.1.76",
    )

    assert json.loads(current_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "source_revision": "deadbeef",
        "version": "3.1.76",
    }
