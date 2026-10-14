"""Universal Windows Setup enrollment orchestration contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from pc_agent.windows_setup import (
    SetupConfig,
    SetupProvisionError,
    UniversalWindowsSetup,
)


class _Transport:
    def __init__(self) -> None:
        self.created: list[dict[str, object]] = []
        self.status_proofs: list[tuple[UUID, str]] = []
        self.claim_proofs: list[tuple[UUID, dict[str, str]]] = []
        self.verification_proofs: list[tuple[UUID, str]] = []

    def create_request(self, body: dict[str, object]) -> dict[str, object]:
        self.created.append(body)
        return {
            "request_id": "6bbc8a59-8429-42f5-9687-36153cd89844",
            "status": "auto_approved",
        }

    def request_status(self, request_id: UUID, capability: str) -> dict[str, object]:
        self.status_proofs.append((request_id, capability))
        return {"status": "auto_approved"}

    def request_claim(self, request_id: UUID, proof: dict[str, str]) -> dict[str, object]:
        self.claim_proofs.append((request_id, proof))
        return {"claim": "ic_claim-marker", "expires_at": "2026-09-19T12:15:00Z"}

    def request_verification(self, request_id: UUID, capability: str) -> dict[str, object]:
        self.verification_proofs.append((request_id, capability))
        return {"status": "completed"}


def test_auto_setup_never_selects_campaign_and_provisions_claim_from_memory() -> None:
    transport = _Transport()
    provisioned: list[str] = []
    setup = UniversalWindowsSetup(
        SetupConfig(
            endpoint_origin="https://endpoint.sosnadmin.local",
            ca_file=Path("C:/ProgramData/Endpoint Platform/Agent/endpoint-ca.crt"),
            installer_version="1.0.0",
            installer_release_id="1.0.0",
        ),
        transport=transport,
        provision_claim=provisioned.append,
        fingerprint_probe=lambda: "sha256:windows-fingerprint-v1",
        inventory_probe=lambda: {"hostname": "office-pc-01", "macs": ["aabbccddeeff"]},
        capability_factory=lambda: "a" * 43,
        installation_id_factory=lambda: "win-00112233-4455-6677-8899-aabbccddeeff",
        clock=lambda: datetime(2026, 9, 19, 12, tzinfo=UTC),
        sleep=lambda _: None,
    )

    outcome = setup.run()

    assert outcome.status == "provisioned"
    assert provisioned == ["ic_claim-marker"]
    assert transport.created[0]["platform"] == "windows"
    assert "campaign_id" not in transport.created[0]
    assert transport.claim_proofs == [
        (
            UUID("6bbc8a59-8429-42f5-9687-36153cd89844"),
            {
                "request_capability": "a" * 43,
                "installation_id": "win-00112233-4455-6677-8899-aabbccddeeff",
                "hardware_fingerprint": "sha256:windows-fingerprint-v1",
            },
        )
    ]
    assert transport.verification_proofs == [
        (UUID("6bbc8a59-8429-42f5-9687-36153cd89844"), "a" * 43)
    ]
    assert "ic_claim-marker" not in repr(outcome)


def test_setup_preserves_safe_provisioner_failure_detail() -> None:
    setup = UniversalWindowsSetup(
        SetupConfig(
            endpoint_origin="https://endpoint.sosnadmin.local",
            ca_file=Path("C:/ProgramData/Endpoint Platform/Agent/endpoint-ca.crt"),
            installer_version="1.0.0",
            installer_release_id="1.0.0",
        ),
        transport=_Transport(),
        provision_claim=lambda _: (_ for _ in ()).throw(
            SetupProvisionError(
                "Windows provisioning failed", detail="PROVISIONER_WINDOWSACLERROR"
            )
        ),
        fingerprint_probe=lambda: "sha256:windows-fingerprint-v1",
        inventory_probe=lambda: {"hostname": "office-pc-01", "macs": []},
        capability_factory=lambda: "a" * 43,
        installation_id_factory=lambda: "win-test",
    )

    with pytest.raises(SetupProvisionError) as raised:
        setup.run()

    assert raised.value.detail == "PROVISIONER_WINDOWSACLERROR"


@pytest.mark.parametrize('decision,want', [('approved','provisioned'), ('denied','denied'), ('expired','expired'), ('cancelled','denied'), ('review_required','timed_out')])
def test_manual_identity_review_waits_for_decision_without_recreating_request(decision, want):
    from datetime import timedelta
    class ReviewTransport(_Transport):
        def create_request(self, body):
            response = super().create_request(body)
            response['status'] = 'review_required'
            return response
        def request_status(self, request_id, capability):
            assert not self.claim_proofs
            super().request_status(request_id, capability)
            return {'status': 'review_required' if len(self.status_proofs) == 1 else decision}
    transport = ReviewTransport()
    provisioned = []
    now = [datetime(2026, 9, 19, 12, tzinfo=UTC)]
    def sleep(_):
        now[0] += timedelta(minutes=10)
    setup = UniversalWindowsSetup(
        SetupConfig(endpoint_origin='https://endpoint.sosnadmin.local', ca_file=Path('ca.crt'), installer_version='1.0.0', installer_release_id='1.0.0'),
        transport=transport, provision_claim=provisioned.append,
        fingerprint_probe=lambda: 'sha256:windows-fingerprint-v1',
        inventory_probe=lambda: {'hostname':'review-pc','macs':[]},
        capability_factory=lambda:'a'*43, installation_id_factory=lambda:'win-review',
        clock=lambda:now[0], sleep=sleep,
    )
    outcome = setup.run()
    assert outcome.status == want
    assert len(transport.created) == 1
    request_id = UUID('6bbc8a59-8429-42f5-9687-36153cd89844')
    assert transport.status_proofs == [(request_id,'a'*43)] * (3 if want == 'timed_out' else 2)
    if want == 'provisioned':
        assert provisioned == ['ic_claim-marker']
        assert transport.claim_proofs == [(request_id,{'request_capability':'a'*43,'installation_id':'win-review','hardware_fingerprint':'sha256:windows-fingerprint-v1'})]
    else:
        assert not provisioned and not transport.claim_proofs and not transport.verification_proofs
    assert now[0] <= datetime(2026,9,19,12,30,tzinfo=UTC)
