from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import traceback
from uuid import UUID, uuid4

import httpx
import pytest


SDK_ROOT = Path(__file__).resolve().parents[2] / "sdk" / "python"
sys.path.insert(0, str(SDK_ROOT))

from endpoint_platform_client import (  # noqa: E402
    EndpointPlatformConfigurationError,
    EndpointPlatformInvalidRequest,
    EndpointPlatformMalformedResponse,
    EndpointPlatformResponseError,
    EndpointPlatformUnavailable,
    EndpointProvisioningClient,
)
import endpoint_platform_client.provisioning as provisioning_module  # noqa: E402


class FakeHttpClient:
    def __init__(
        self, *, responses: list[httpx.Response | Exception], **kwargs: object
    ) -> None:
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


def provisioning_token(tmp_path: Path) -> Path:
    path = tmp_path / "endpoint-provisioning.token"
    path.write_text("provisioning-token-marker\n", encoding="utf-8")
    return path


def ca(tmp_path: Path) -> Path:
    path = tmp_path / "endpoint-platform-ca.pem"
    path.write_text(
        "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    return path


def response(status_code: int, payload: object) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def _claim_value() -> str:
    return "ic_" + ("a" * 32) + "." + ("b" * 43)


def _claim_response(
    *, install_session_id: str, expires_at: object
) -> dict[str, object]:
    return {
        "claim": _claim_value(),
        "expires_at": expires_at,
        "install_session_id": install_session_id,
    }


def _future_expiry() -> str:
    return (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")


def _captured_traceback(exc: pytest.ExceptionInfo[Exception]) -> str:
    return "".join(
        traceback.TracebackException(
            exc.type,
            exc.value,
            exc.tb,
            capture_locals=True,
        ).format()
    )


def _assert_claim_is_absent_from_captured_traceback(
    exc: pytest.ExceptionInfo[Exception],
) -> None:
    assert _claim_value() not in _captured_traceback(exc)


def _assert_bad_token_is_absent_from_captured_traceback(
    exc: pytest.ExceptionInfo[Exception],
) -> None:
    assert "bad-provisioning-token-marker" not in _captured_traceback(exc)


def _write_bad_provisioning_token(tmp_path: Path) -> Path:
    path = tmp_path / "endpoint-provisioning.token"
    path.write_text("bad-provisioning-token-marker" + ("x" * 4096), encoding="utf-8")
    return path


class OversizedResponse:
    status_code = 201
    headers = {"Content-Length": "16385"}
    content = b"x" * 16385

    def json(self) -> object:
        raise AssertionError(
            "response JSON parser must not be called for oversized bodies"
        )


def _client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    responses: list[httpx.Response | Exception],
) -> tuple[EndpointProvisioningClient, FakeHttpClient]:
    fake = FakeHttpClient(responses=responses)

    def build(**kwargs: object) -> FakeHttpClient:
        fake.kwargs = kwargs
        return fake

    monkeypatch.setattr(provisioning_module.httpx, "Client", build)
    return (
        EndpointProvisioningClient(
            "https://endpoint.invalid",
            provisioning_token_file=provisioning_token(tmp_path),
            ca_file=ca(tmp_path),
        ),
        fake,
    )


def test_issue_install_claim_posts_the_only_provisioning_operation_and_returns_a_secret_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_id = uuid4()
    claim_marker = _claim_value()
    client, fake = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                _claim_response(
                    install_session_id="alt-install-001",
                    expires_at=_future_expiry(),
                ),
            )
        ],
    )

    claim = client.issue_install_claim(
        "alt-install-001",
        "sha256:fixture-hardware-fingerprint-01",
        campaign_id,
    )

    assert claim.get_secret_value() == claim_marker
    assert claim.install_session_id == "alt-install-001"
    assert claim.expires_at > datetime.now(UTC)
    assert claim_marker not in str(claim)
    assert claim_marker not in repr(claim)
    assert claim_marker not in repr(asdict(claim))
    assert fake.kwargs["verify"] == str(ca(tmp_path))
    assert fake.kwargs["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer provisioning-token-marker",
    }
    assert fake.calls == [
        (
            "POST",
            "/api/v1/provisioning/install-claims",
            {
                "json": {
                    "install_session_id": "alt-install-001",
                    "hardware_fingerprint": "sha256:fixture-hardware-fingerprint-01",
                    "campaign_id": str(campaign_id),
                }
            },
        )
    ]


@pytest.mark.parametrize(
    ("install_session_id", "hardware_fingerprint", "campaign_id"),
    [
        (" bad", "sha256:fixture-hardware-fingerprint-01", uuid4()),
        ("x" * 129, "sha256:fixture-hardware-fingerprint-01", uuid4()),
        ("alt-install-001", "sha256:_not-a-fingerprint", uuid4()),
        ("alt-install-001", "sha256:a", uuid4()),
        ("alt-install-001", "sha256:fixture-hardware-fingerprint-01", "not-a-uuid"),
    ],
)
def test_issue_install_claim_rejects_invalid_public_contract_input_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_session_id: str,
    hardware_fingerprint: str,
    campaign_id: UUID | str,
) -> None:
    client, fake = _client(tmp_path, monkeypatch, [])

    with pytest.raises(EndpointPlatformInvalidRequest):
        client.issue_install_claim(
            install_session_id, hardware_fingerprint, campaign_id
        )  # type: ignore[arg-type]

    assert fake.calls == []


def test_provisioning_client_never_retries_and_traceback_redacts_claim_token_and_raw_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unsafe_claim = _claim_value()
    client, fake = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                503,
                {
                    "claim": unsafe_claim,
                    "token": "provisioning-token-marker",
                    "detail": "raw body",
                },
            )
        ],
    )

    with pytest.raises(EndpointPlatformResponseError) as exc:
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )

    rendered = "".join(traceback.format_exception(exc.type, exc.value, exc.tb))
    assert unsafe_claim not in rendered
    assert "provisioning-token-marker" not in rendered
    assert "raw body" not in rendered
    assert exc.value.__cause__ is None
    assert len(fake.calls) == 1


def test_provisioning_client_redacts_request_transport_failure_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, fake = _client(
        tmp_path,
        monkeypatch,
        [
            httpx.ConnectError(
                "provisioning-token-marker " + ("ic_" + ("a" * 32) + "." + ("b" * 43))
            )
        ],
    )

    with pytest.raises(EndpointPlatformUnavailable) as exc:
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )

    rendered = "".join(traceback.format_exception(exc.type, exc.value, exc.tb))
    assert "provisioning-token-marker" not in rendered
    assert _claim_value() not in rendered
    assert exc.value.__cause__ is None
    assert len(fake.calls) == 1


def test_provisioning_response_is_strict_and_does_not_retain_claim_in_error_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                {
                    **_claim_response(
                        install_session_id="alt-install-001",
                        expires_at=_future_expiry(),
                    ),
                    "unexpected": "raw response",
                },
            )
        ],
    )

    with pytest.raises(EndpointPlatformMalformedResponse) as exc:
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )

    rendered = "".join(traceback.format_exception(exc.type, exc.value, exc.tb))
    assert "ic_" + ("a" * 32) + "." + ("b" * 43) not in rendered
    assert "raw response" not in rendered
    assert exc.value.__cause__ is None


def test_provisioning_response_must_echo_the_requested_install_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                _claim_response(
                    install_session_id="different-install-session",
                    expires_at=_future_expiry(),
                ),
            )
        ],
    )

    with pytest.raises(EndpointPlatformMalformedResponse):
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )


def test_provisioning_response_rejects_an_expired_claim_before_returning_its_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                _claim_response(
                    install_session_id="alt-install-001",
                    expires_at="2020-01-01T00:00:00Z",
                ),
            )
        ],
    )

    with pytest.raises(EndpointPlatformMalformedResponse):
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )


def test_provisioning_client_requires_https_and_usable_ca_and_token_files(
    tmp_path: Path,
) -> None:
    with pytest.raises(EndpointPlatformConfigurationError):
        EndpointProvisioningClient(
            "http://endpoint.invalid",
            provisioning_token_file=provisioning_token(tmp_path),
            ca_file=ca(tmp_path),
        )


@pytest.mark.parametrize("expires_at", [1_785_000_000, "2026-07-30T15:00:00+03:00"])
def test_provisioning_response_requires_a_utc_z_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expires_at: object
) -> None:
    client, _ = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                _claim_response(
                    install_session_id="alt-install-001", expires_at=expires_at
                ),
            )
        ],
    )

    with pytest.raises(EndpointPlatformMalformedResponse):
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )


def test_provisioning_client_rejects_oversized_body_before_json_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(tmp_path, monkeypatch, [OversizedResponse()])  # type: ignore[list-item]

    with pytest.raises(EndpointPlatformMalformedResponse):
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )


@pytest.mark.parametrize(
    "response_session, expires_at",
    [
        ("different-install-session", _future_expiry()),
        ("alt-install-001", "2020-01-01T00:00:00Z"),
    ],
)
def test_capture_locals_traceback_redacts_claim_after_response_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response_session: str,
    expires_at: str,
) -> None:
    client, _ = _client(
        tmp_path,
        monkeypatch,
        [
            response(
                201,
                _claim_response(
                    install_session_id=response_session, expires_at=expires_at
                ),
            )
        ],
    )

    with pytest.raises(EndpointPlatformMalformedResponse) as exc:
        client.issue_install_claim(
            "alt-install-001",
            "sha256:fixture-hardware-fingerprint-01",
            uuid4(),
        )

    _assert_claim_is_absent_from_captured_traceback(exc)


def test_capture_locals_traceback_redacts_bad_provisioning_token_configuration(
    tmp_path: Path,
) -> None:
    with pytest.raises(EndpointPlatformConfigurationError) as exc:
        EndpointProvisioningClient(
            "https://endpoint.invalid",
            provisioning_token_file=_write_bad_provisioning_token(tmp_path),
            ca_file=ca(tmp_path),
        )

    _assert_bad_token_is_absent_from_captured_traceback(exc)
