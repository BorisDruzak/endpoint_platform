from __future__ import annotations

from pathlib import Path
import sys
from uuid import UUID, uuid4

import httpx
import pytest


SDK_ROOT = Path(__file__).resolve().parents[2] / "sdk" / "python"
sys.path.insert(0, str(SDK_ROOT))

from endpoint_platform_client import (  # noqa: E402
    EndpointPlatformClient,
    EndpointPlatformConfigurationError,
    EndpointPlatformInvalidRequest,
    EndpointPlatformMalformedResponse,
    EndpointPlatformResponseError,
    EndpointPlatformUnavailable,
)
import endpoint_platform_client.client as client_module  # noqa: E402


class FakeHttpClient:
    def __init__(self, *, responses: list[httpx.Response | Exception], **kwargs: object) -> None:
        self.responses = responses
        self.kwargs = kwargs
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        self.calls.append((method, path, kwargs))
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self) -> None:
        return None


def token(tmp_path: Path) -> Path:
    path = tmp_path / "endpoint-platform.token"
    path.write_text("secret-token\n", encoding="utf-8")
    return path


def ca(tmp_path: Path) -> Path:
    path = tmp_path / "endpoint-platform-ca.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n", encoding="utf-8")
    return path


def _response(status_code: int, payload: object) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def _device_payload(device_id: str) -> dict[str, object]:
    return {
        "data": [
            {
                "id": device_id,
                "device_identifier": "workstation-001",
                "display_name": "Workstation 001",
                "retired_at": None,
            }
        ]
    }


def _baseline_snapshot(snapshot_id: str) -> dict[str, object]:
    return {
        "id": snapshot_id,
        "profile": "baseline_v1",
        "collected_at": "2026-07-29T10:00:00Z",
        "semantic_hash": "a" * 64,
        "warnings": [],
        "sections": {
            "system": {"platform": "linux", "distribution": "ALT", "architecture": "x86_64"},
            "hardware": {"manufacturer": "Acme", "model": "A1", "cpu_model": "CPU", "memory_bytes": 1024},
            "storage": [{"stable_key": "disk:one", "model": "Disk", "size_bytes": 2048}],
            "interfaces": [],
            "software": [],
        },
    }


def test_client_uses_ca_and_redacts_token_on_unavailable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[FakeHttpClient] = []

    def build(**kwargs: object) -> FakeHttpClient:
        fake = FakeHttpClient(
            responses=[
                httpx.ConnectError("Bearer secret-token connection refused"),
                httpx.ConnectError("Bearer secret-token connection refused"),
                httpx.ConnectError("Bearer secret-token connection refused"),
            ],
            **kwargs,
        )
        created.append(fake)
        return fake

    monkeypatch.setattr(client_module.httpx, "Client", build)
    client = EndpointPlatformClient(
        "https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path), timeout_seconds=2
    )

    with pytest.raises(EndpointPlatformUnavailable) as exc:
        client.list_devices()

    assert "secret-token" not in str(exc.value)
    assert len(created[0].calls) == 3
    assert created[0].kwargs["verify"] == str(ca(tmp_path))
    assert created[0].kwargs["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer secret-token",
    }


def test_tls_initialization_failure_is_a_redacted_configuration_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        client_module.httpx,
        "Client",
        lambda **_: (_ for _ in ()).throw(OSError("C:/private/endpoint-platform-ca.pem secret-token")),
    )

    with pytest.raises(EndpointPlatformConfigurationError) as exc:
        EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    assert "secret-token" not in str(exc.value)
    assert "endpoint-platform-ca.pem" not in str(exc.value)


def test_get_retries_a_bounded_number_of_times_and_returns_typed_devices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    device_id = str(uuid4())
    fake = FakeHttpClient(
        responses=[
            _response(503, {"raw_error": "do not expose"}),
            _response(200, _device_payload(device_id)),
        ]
    )
    monkeypatch.setattr(client_module.httpx, "Client", lambda **_: fake)
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    devices = client.list_devices()

    assert [device.id for device in devices] == [UUID(device_id)]
    assert len(fake.calls) == 2
    assert all(method == "GET" for method, _, _ in fake.calls)
    assert fake.calls[0][1] == "/api/v1/devices"


def test_post_never_retries_and_redacts_http_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttpClient(responses=[_response(503, {"token": "secret-token", "detail": "down"})])
    monkeypatch.setattr(client_module.httpx, "Client", lambda **_: fake)
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    with pytest.raises(EndpointPlatformResponseError) as exc:
        client.request_collection(uuid4(), "baseline_v1", "request-1")

    assert "secret-token" not in str(exc.value)
    assert len(fake.calls) == 1
    method, path, kwargs = fake.calls[0]
    assert method == "POST"
    assert path.endswith("/context/collections")
    assert kwargs["headers"] == {"Idempotency-Key": "request-1"}
    assert kwargs["json"] == {"profile": "baseline_v1"}


def test_diagnostic_profile_is_rejected_before_transport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttpClient(responses=[])
    monkeypatch.setattr(client_module.httpx, "Client", lambda **_: fake)
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    with pytest.raises(EndpointPlatformInvalidRequest):
        client.request_collection(uuid4(), "diagnostic_v1", "request-1")  # type: ignore[arg-type]

    assert fake.calls == []


def test_malformed_safe_response_becomes_typed_redacted_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttpClient(responses=[_response(200, {"data": [{"id": "not-a-uuid"}]})])
    monkeypatch.setattr(client_module.httpx, "Client", lambda **_: fake)
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    with pytest.raises(EndpointPlatformMalformedResponse) as exc:
        client.list_devices()

    assert "not-a-uuid" not in str(exc.value)


def test_safe_read_methods_validate_normalized_service_projections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    device_id = uuid4()
    snapshot_id = uuid4()
    other_snapshot_id = uuid4()
    collection_id = uuid4()
    snapshot = _baseline_snapshot(str(snapshot_id))
    device = _device_payload(str(device_id))
    fake = FakeHttpClient(
        responses=[
            _response(200, device),
            _response(200, {"data": {"device": device["data"][0], "profiles": [{"profile": "baseline_v1", "status": "completed", "last_collected_at": "2026-07-29T10:00:00Z"}], "snapshots": [snapshot]}}),
            _response(200, {"data": {"collection": {"id": str(collection_id), "device_id": str(device_id), "profile": "baseline_v1", "status": "completed", "requested_at": "2026-07-29T09:59:00Z", "result_received_at": "2026-07-29T10:00:00Z", "completed_at": "2026-07-29T10:00:00Z", "failure_code": None}, "snapshot": snapshot}}),
            _response(200, {"data": {"schema_version": "device_context_diff_v1", "profile": "baseline_v1", "from_hash": "b" * 64, "to_hash": "c" * 64, "changes": [{"code": "hardware_changed", "summary": "Hardware changed"}]}}),
        ]
    )
    monkeypatch.setattr(client_module.httpx, "Client", lambda **_: fake)
    client = EndpointPlatformClient("https://endpoint.invalid", token_file=token(tmp_path), ca_file=ca(tmp_path))

    found = client.get_device(device_id)
    latest = client.get_latest_context(device_id, "baseline_v1")
    details = client.get_collection(collection_id)
    comparison = client.compare_context(device_id, snapshot_id, other_snapshot_id)

    assert found.id == device_id
    assert latest is not None and latest.id == snapshot_id
    assert details.collection.id == collection_id
    assert details.snapshot is not None and details.snapshot.profile == "baseline_v1"
    assert comparison.comparison.changes[0].code == "hardware_changed"
    assert fake.calls[-1][1].endswith("/context/snapshots/compare")
    assert fake.calls[-1][2]["params"] == {
        "before_snapshot_id": str(snapshot_id),
        "after_snapshot_id": str(other_snapshot_id),
    }
