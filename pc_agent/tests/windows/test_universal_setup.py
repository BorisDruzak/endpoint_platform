"""Universal Windows Setup enrollment orchestration contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from pc_agent.windows_setup import SetupConfig, UniversalWindowsSetup


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
