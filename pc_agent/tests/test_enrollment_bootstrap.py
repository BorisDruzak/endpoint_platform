from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from uuid import UUID

import pytest

import pc_agent.enrollment_bootstrap as enrollment_bootstrap
from pc_agent.enrollment_bootstrap import (
    BootstrapConfig,
    EnrollmentDelivery,
    EnrollmentRejected,
    EnrollmentTemporaryFailure,
    bootstrap_enrollment,
)


_CLAIM = "ic_0123456789abcdef0123456789abcdef.abcdefghijklmnopqrstuvwxyzABCDEFG"
_TOKEN = "A" * 43
_FINGERPRINT = "sha256:agent-bootstrap-hardware-001"


class _Transport:
    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes = outcomes
        self.requests: list[tuple[str, str, str, str]] = []

    async def enroll(
        self,
        *,
        endpoint_url: str,
        ca_file: Path,
        claim: str,
        request: dict[str, object],
    ) -> EnrollmentDelivery:
        self.requests.append(
            (
                endpoint_url,
                str(ca_file),
                claim,
                str(request["hardware_fingerprint"]),
            )
        )
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, EnrollmentDelivery)
        return outcome


def _config(tmp_path: Path) -> BootstrapConfig:
    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("test-ca", encoding="utf-8")
    return BootstrapConfig(
        endpoint_url="https://endpoint.example.test",
        ca_file=ca_file,
        installation_id="alt-install-001",
        credential_path=enrollment_bootstrap.PERMANENT_CREDENTIAL_PATH,
        handoff_request_path=enrollment_bootstrap.HANDOFF_REQUEST_PATH,
        # The production path is Linux-only.  The unit test runs on Windows,
        # where stat reports the synthetic zero owner/group.
        service_uid=0,
        service_gid=0,
        retry_attempts=3,
    )


def _credential_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "credentials"
    directory.mkdir()
    claim = directory / "endpoint-enrollment-claim"
    claim.write_text(_CLAIM, encoding="utf-8")
    claim.chmod(0o400)
    return directory


def _delivery() -> EnrollmentDelivery:
    return EnrollmentDelivery(
        device_id=UUID("9c83f6de-3435-4fc3-a7e0-7bcddc744f3b"),
        device_token=_TOKEN,
    )


@pytest.fixture(autouse=True)
def _isolated_fixed_production_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tests replace constants, never the BootstrapConfig runtime API."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setattr(
        enrollment_bootstrap, "PERMANENT_CREDENTIAL_PATH", state / "device-credential"
    )
    monkeypatch.setattr(
        enrollment_bootstrap,
        "HANDOFF_REQUEST_PATH",
        state / "claim-removal-request.json",
    )


def test_bootstrap_configuration_rejects_arbitrary_credential_and_handoff_paths(
    tmp_path: Path,
) -> None:
    """The unprivileged runtime must not choose root-finalizer locations."""
    ca_file = tmp_path / "ca.crt"
    ca_file.write_text("test-ca", encoding="utf-8")
    config = BootstrapConfig(
        endpoint_url="https://endpoint.example.test",
        ca_file=ca_file,
        installation_id="alt-install-001",
        credential_path=tmp_path / "unsafe" / "device-credential",
        handoff_request_path=tmp_path / "unsafe" / "claim-removal-request.json",
        service_uid=0,
        service_gid=0,
    )

    with pytest.raises(ValueError, match="fixed production locations"):
        config.validate()


@pytest.mark.asyncio
async def test_success_persists_verified_service_credential_before_nonsecret_root_handoff(
    tmp_path: Path,
) -> None:
    """Catches deleting a one-time claim before the durable credential exists."""
    config = _config(tmp_path)
    credentials_dir = _credential_dir(tmp_path)
    transport = _Transport([_delivery()])

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
    )

    assert result.status == "enrolled"
    assert result.device_id == "9c83f6de-3435-4fc3-a7e0-7bcddc744f3b"
    credential = config.credential_path
    assert credential.read_text(encoding="utf-8") == _TOKEN
    metadata = credential.stat()
    if os.name != "nt":
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert (metadata.st_uid, metadata.st_gid) == (
            config.service_uid,
            config.service_gid,
        )
    assert (credentials_dir / "endpoint-enrollment-claim").read_text() == _CLAIM
    handoff = config.handoff_request_path.read_text(encoding="utf-8")
    assert _CLAIM not in handoff
    assert _TOKEN not in handoff
    handoff_payload = json.loads(handoff)
    assert handoff_payload == {
        "schema_version": "endpoint_claim_removal_request_v1",
        "claim_credential_name": "endpoint-enrollment-claim",
        "credential_path": str(config.credential_path),
        "device_id": "9c83f6de-3435-4fc3-a7e0-7bcddc744f3b",
        "credential_sha256": hashlib.sha256(_TOKEN.encode("ascii")).hexdigest(),
    }
    assert transport.requests == [
        (
            "https://endpoint.example.test",
            str(config.ca_file),
            _CLAIM,
            _FINGERPRINT,
        )
    ]


@pytest.mark.asyncio
async def test_temporary_gateway_outage_retries_a_fixed_budget_without_partial_credential(
    tmp_path: Path,
) -> None:
    """Catches unbounded retries or a partial token write during an outage."""
    config = _config(tmp_path)
    credentials_dir = _credential_dir(tmp_path)
    transport = _Transport(
        [
            EnrollmentTemporaryFailure(),
            EnrollmentTemporaryFailure(),
            EnrollmentTemporaryFailure(),
        ]
    )

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
        sleep=lambda _: asyncio.sleep(0),
    )

    assert result.status == "temporary_failure"
    assert len(transport.requests) == 3
    assert not config.credential_path.exists()
    assert not config.handoff_request_path.exists()
    assert (credentials_dir / "endpoint-enrollment-claim").read_text() == _CLAIM


@pytest.mark.asyncio
async def test_rejected_or_wrong_claim_fails_closed_without_retry_or_secret_logging(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Catches retrying replay/mismatch failures or exposing one-time material."""
    config = _config(tmp_path)
    credentials_dir = _credential_dir(tmp_path)
    transport = _Transport([EnrollmentRejected("denied")])
    caplog.set_level(logging.DEBUG)

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
    )

    assert result.status == "denied"
    assert len(transport.requests) == 1
    assert not config.credential_path.exists()
    assert not config.handoff_request_path.exists()
    rendered_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert _CLAIM not in rendered_logs
    assert _TOKEN not in rendered_logs


@pytest.mark.asyncio
async def test_existing_verified_credential_preserves_identity_without_rereading_claim(
    tmp_path: Path,
) -> None:
    """Catches re-enrolling an already provisioned service after a restart."""
    config = _config(tmp_path)
    config.credential_path.parent.mkdir(exist_ok=True)
    config.credential_path.write_text(_TOKEN, encoding="utf-8")
    config.credential_path.chmod(0o600)
    transport = _Transport([])

    result = await bootstrap_enrollment(
        tmp_path / "no-credentials-directory",
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
    )

    assert result.status == "already_enrolled"
    assert transport.requests == []


@pytest.mark.asyncio
async def test_legacy_task15_systemd_credential_name_is_rejected_by_the_fixed_protocol(
    tmp_path: Path,
) -> None:
    """Only the service's reviewed credential name may reach finalization."""
    config = _config(tmp_path)
    config = BootstrapConfig(
        **{
            **config.__dict__,
            "claim_credential_name": "endpoint-agent-provisioning-handoff",
        }
    )
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    (credentials_dir / "endpoint-agent-provisioning-handoff").write_text(
        _CLAIM, encoding="utf-8"
    )
    transport = _Transport([_delivery()])

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
    )

    assert result.status == "credential_invalid"
    assert transport.requests == []


@pytest.mark.asyncio
async def test_failed_postwrite_verification_removes_the_just_written_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches leaving a partial permanent credential after verification fails."""
    config = _config(tmp_path)
    credentials_dir = _credential_dir(tmp_path)
    monkeypatch.setattr(
        enrollment_bootstrap, "_verified_credential_matches", lambda *_, **__: False
    )

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=_Transport([_delivery()]),
    )

    assert result.status == "persistence_failed"
    assert not config.credential_path.exists()
    assert not config.handoff_request_path.exists()


@pytest.mark.asyncio
async def test_symlink_claim_source_is_rejected_before_any_enrollment_or_write(
    tmp_path: Path,
) -> None:
    """Catches following an attacker-controlled credential source."""
    config = _config(tmp_path)
    credentials_dir = tmp_path / "credentials"
    credentials_dir.mkdir()
    original = tmp_path / "claim-source"
    original.write_text(_CLAIM, encoding="utf-8")
    (credentials_dir / "endpoint-enrollment-claim").symlink_to(original)
    transport = _Transport([])

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=transport,
    )

    assert result.status == "denied"
    assert transport.requests == []
    assert not config.credential_path.exists()
    assert not config.handoff_request_path.exists()


@pytest.mark.asyncio
async def test_symlink_request_parent_leaves_verified_credential_and_claim_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches following a symlink while preparing the root-finalizer request."""
    unsafe_parent = tmp_path / "unsafe-request-parent"
    target_parent = tmp_path / "request-target"
    target_parent.mkdir()
    unsafe_parent.symlink_to(target_parent, target_is_directory=True)
    monkeypatch.setattr(
        enrollment_bootstrap,
        "HANDOFF_REQUEST_PATH",
        unsafe_parent / "claim-removal-request.json",
    )
    config = _config(tmp_path)
    credentials_dir = _credential_dir(tmp_path)

    result = await bootstrap_enrollment(
        credentials_dir,
        config,
        probe=lambda: _FINGERPRINT,
        transport=_Transport([_delivery()]),
    )

    assert result.status == "handoff_pending"
    assert config.credential_path.read_text(encoding="ascii") == _TOKEN
    assert (credentials_dir / "endpoint-enrollment-claim").read_text() == _CLAIM
    assert not config.handoff_request_path.exists()
