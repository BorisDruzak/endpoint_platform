"""Windows one-time enrollment provisioning contracts."""

from __future__ import annotations

import io
import re
from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest


_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000611")
_TOKEN = "t" * 43
_CLAIM = "claim-not-a-command-line-property"


class _Acl:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def protect_directory(self, path: Path) -> None:
        self.events.append(f"acl.directory:{path.name}")

    def protect_credential(self, path: Path) -> None:
        self.events.append(f"acl.credential:{path.name}")

    def protect_claim(self, path: Path) -> None:
        self.events.append(f"acl.claim:{path.name}")

    def assert_protected_file(self, path: Path) -> None:
        self.events.append(f"acl.source:{path.name}")


class _Service:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def start(self) -> None:
        self.events.append("service.start")


class _Enrollment:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def enroll(self, *, claim: str, endpoint_origin: str, ca_file: Path):
        assert claim == _CLAIM
        assert endpoint_origin == "https://endpoint.sosnadmin.local"
        assert ca_file.name == "endpoint-ca.crt"
        self.events.append("gateway.enroll")
        from pc_agent.platform.windows.provision import EnrollmentDelivery

        return EnrollmentDelivery(device_id=_DEVICE_ID, device_token=_TOKEN)


def _request(tmp_path: Path):
    import certifi
    from pc_agent.platform.windows.provision import ProvisioningRequest

    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_bytes(Path(certifi.where()).read_bytes())
    return ProvisioningRequest(
        endpoint_origin="https://endpoint.sosnadmin.local",
        ca_file=ca_file,
        data_root=tmp_path / "protected-data",
    )


@pytest.mark.parametrize("origin", ["http://endpoint.sosnadmin.local", "https://user@endpoint.sosnadmin.local", "https://endpoint.sosnadmin.local/path", "https://:", "https://endpoint.sosnadmin.local:bad", "https://foo bar", "https://foo_bar.example", "https://%41.example", "https://.example", "https://example..com"])
def test_provisioning_rejects_non_origin_https_endpoint(tmp_path: Path, origin: str) -> None:
    """Accepting a route, HTTP, or credentialed URL would widen the enrollment target."""
    from pc_agent.platform.windows.provision import ProvisioningRequest

    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test CA", encoding="ascii")
    request = ProvisioningRequest(origin, ca_file, tmp_path / "data")

    with pytest.raises(ValueError, match="absolute HTTPS origin"):
        request.validate()


@pytest.mark.parametrize("origin", ["https://foo bar", "https://foo_bar.example", "https://%41.example", "https://.example", "https://example..com"])
def test_malformed_origin_is_rejected_before_enrollment_adapter(
    tmp_path: Path, origin: str
) -> None:
    """A malformed host must not reach the enrollment network boundary."""
    from pc_agent.platform.windows.provision import ProvisioningRequest, WindowsProvisioner

    calls: list[str] = []

    class _NeverEnroll:
        def enroll(self, **_kwargs):
            calls.append("enroll")
            raise AssertionError("invalid host reached enrollment")

    request = _request(tmp_path)
    request = ProvisioningRequest(origin, request.ca_file, request.data_root)
    provisioner = WindowsProvisioner(
        request, enrollment=_NeverEnroll(), service=_Service(calls), acl=_Acl(calls)
    )

    with pytest.raises(ValueError, match="absolute HTTPS origin"):
        provisioner.provision_from_stdin(io.StringIO(_CLAIM))
    assert calls == []


def test_provisioning_requires_the_installed_ca_file(tmp_path: Path) -> None:
    """Provisioning without a local CA must fail before reading enrollment material."""
    request = _request(tmp_path)
    request.ca_file.unlink()

    with pytest.raises(ValueError, match="CA file"):
        request.validate()


def test_provisioning_rejects_non_certificate_ca_content(tmp_path: Path) -> None:
    """A readable arbitrary file must not bypass TLS trust validation."""
    request = _request(tmp_path)
    request.ca_file.write_text("not a certificate", encoding="ascii")

    with pytest.raises(ValueError, match="CA file"):
        request.validate()


def test_provisioner_persists_protected_material_proves_credential_then_starts_service(
    tmp_path: Path,
) -> None:
    """Deleting the claim before durable credential proof risks an unrecoverable install."""
    from pc_agent.platform.windows.provision import WindowsProvisioner

    events: list[str] = []
    request = _request(tmp_path)
    provisioner = WindowsProvisioner(
        request,
        enrollment=_Enrollment(events),
        service=_Service(events),
        acl=_Acl(events),
    )

    result = provisioner.provision_from_stdin(io.StringIO(_CLAIM))

    claim_path = request.data_root / "enrollment-claim"
    credential_path = request.data_root / "device-credential"
    identity_path = request.data_root / "enrollment-identity.json"
    installed_ca_path = request.data_root / "endpoint-ca.crt"
    assert result.device_id == _DEVICE_ID
    assert result.claim_removed is True
    assert not claim_path.exists()
    assert installed_ca_path.read_bytes() == request.ca_file.read_bytes()
    assert credential_path.read_text(encoding="ascii") == _TOKEN
    assert _DEVICE_ID.hex in identity_path.read_text(encoding="ascii").replace("-", "")
    assert events == [
        "acl.directory:protected-data",
        "acl.claim:enrollment-claim",
        "gateway.enroll",
        "acl.credential:endpoint-ca.crt",
        "acl.credential:device-credential",
        "service.start",
    ]


def test_provisioner_reads_material_from_a_protected_file_without_echoing_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A protected-file path is allowed, but claim material must not become CLI output."""
    from pc_agent.platform.windows.provision import WindowsProvisioner

    request = _request(tmp_path)
    source = tmp_path / "installer-input"
    source.write_text(_CLAIM, encoding="ascii")
    events: list[str] = []
    provisioner = WindowsProvisioner(
        request,
        enrollment=_Enrollment(events),
        service=_Service(events),
        acl=_Acl(events),
    )

    provisioner.provision_from_protected_file(source)

    assert "acl.source:installer-input" in events
    assert _CLAIM not in capsys.readouterr().out


def test_provisioner_cli_reports_only_failure_type_without_enrollment_material(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failed packaged provisioner must be diagnosable without leaking its claim."""
    from pc_agent.platform.windows import provision

    class _FailingProvisioner:
        def provision_from_stdin(self) -> None:
            raise RuntimeError(_CLAIM)

    monkeypatch.setattr(provision, "WindowsProvisioner", lambda _request: _FailingProvisioner())

    assert provision.main([
        "--endpoint-origin", "https://endpoint.sosnadmin.local",
        "--ca-file", str(tmp_path / "endpoint-ca.crt"),
        "--data-dir", str(tmp_path / "data"),
        "--installation-id", "diagnostic-contract",
    ]) == 1

    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert _CLAIM not in captured.out + captured.err


def test_provisioner_uses_atomic_replace_for_claim_and_permanent_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A direct write can expose a partial claim or credential after interruption."""
    from pc_agent.platform.windows import provision

    request = _request(tmp_path)
    events: list[str] = []
    replacements: list[tuple[Path, Path]] = []
    original_replace = provision.os.replace

    def capture_replace(source, target) -> None:
        replacements.append((Path(source), Path(target)))
        original_replace(source, target)

    monkeypatch.setattr(provision.os, "replace", capture_replace)
    WindowsProvisioner = provision.WindowsProvisioner
    WindowsProvisioner(
        request,
        enrollment=_Enrollment(events),
        service=_Service(events),
        acl=_Acl(events),
    ).provision_from_stdin(io.StringIO(_CLAIM))

    assert [target.name for _source, target in replacements] == [
        "enrollment-claim",
        "endpoint-ca.crt",
        "device-credential",
        "enrollment-identity.json",
    ]
    assert all(source.name.startswith(".") for source, _target in replacements)
    assert not list(request.data_root.glob(".*"))


def test_windows_acl_contract_keeps_ordinary_users_off_the_credential() -> None:
    """Adding Users or granting the updater read would expose the device bearer."""
    from pc_agent.platform.windows.acl import CREDENTIAL_ACL, EXPECTED_PRINCIPALS

    assert EXPECTED_PRINCIPALS == (
        "SYSTEM",
        "Administrators",
        "NT SERVICE\\EndpointAgent",
        "NT SERVICE\\EndpointAgentUpdater",
    )
    assert {rule.principal for rule in CREDENTIAL_ACL} == set(EXPECTED_PRINCIPALS)
    assert {rule.principal for rule in CREDENTIAL_ACL if rule.rights == "read"} == {
        "NT SERVICE\\EndpointAgent"
    }


def test_https_windows_enrollment_sends_a_valid_windows_contract_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A malformed Windows request would consume a one-time claim without enrollment."""
    from pc_agent.platform.windows import provision
    from pc_agent.enrollment_bootstrap import EnrollmentDelivery

    observed: dict[str, object] = {}

    class _Transport:
        async def enroll(self, **kwargs):
            observed.update(kwargs)
            return EnrollmentDelivery(device_id=_DEVICE_ID, device_token=_TOKEN)

    monkeypatch.setattr(provision, "HttpsEnrollmentTransport", lambda: _Transport())
    monkeypatch.setattr(
        provision, "_derive_hardware_fingerprint", lambda _probe: "sha256:" + "a" * 64
    )

    result = provision.HttpsWindowsEnrollmentClient("windows-contract-001").enroll(
        claim=_CLAIM,
        endpoint_origin="https://endpoint.sosnadmin.local",
        ca_file=tmp_path / "endpoint-ca.crt",
    )

    assert result.device_id == _DEVICE_ID
    assert observed["endpoint_url"] == "https://endpoint.sosnadmin.local"
    request = observed["request"]
    assert request["schema_version"] == "agent_enrollment_request_v1"
    assert request["platform"] == "windows"
    assert request["hardware_fingerprint"] == "sha256:" + "a" * 64
    assert request["installation_id"] == "windows-contract-001"
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", request["delivery_nonce"])
    assert datetime.fromisoformat(request["requested_at"])
    assert _CLAIM not in str(request)
