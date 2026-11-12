"""Exact DEB intake for explicitly approved Linux servers."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from endpoint_contracts.enrollment import PreEnrollmentRequestStatusV1, _SecretSafeContractModelV1
from endpoint_contracts.identity import normalize_install_session_id
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.db.models import EnrollmentClaim, EnrollmentRequest

from .campaigns import EnrollmentDenied, hardware_fingerprint_digest, issue_campaign
from .request_routes import _source_address
from .requests import (
    CampaignSelection,
    build_enrollment_request,
    enrollment_request_rate_limited,
    persist_enrollment_request,
    request_bindings_match,
    request_capability_matches,
)


router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment-requests"])
PACKAGE_VERSION = "3.2.192-1ubuntu1"
PACKAGE_SHA256 = "8affee69264c5cbdc76237ba83dfe5db91ab7a34562ee92f024d9d2b24471a7d"
RELEASE_ID = "ubuntu-deb:" + PACKAGE_VERSION
POLICY_RELEASE = UUID("fb725608-e7da-4c9c-bfa5-2038f2f18a5a")
PILOT_HOSTS = {
    "192.168.100.19": "endpointplatform",
    "192.168.100.27": "dirpost",
    "192.168.100.30": "openvpn",
}


class DebRequest(_SecretSafeContractModelV1):
    _repr_secret_fields = frozenset({"hardware_fingerprint", "request_capability"})
    installation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    hardware_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_capability: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    hostname: str = Field(min_length=1, max_length=63)
    package_version: str = Field(min_length=1, max_length=40)
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class UbuntuDebRequest(DebRequest):
    schema_version: Literal["ubuntu_deb_enrollment_request_v1"]


class DebianDebRequest(DebRequest):
    schema_version: Literal["debian_deb_enrollment_request_v1"]


@dataclass(frozen=True)
class DebSource:
    distro: str
    version: str
    sha256: str
    policy_release: UUID
    hosts: dict[str, str]

    @property
    def release_id(self) -> str:
        return f"{self.distro}-deb:{self.version}"

    @property
    def policy_id(self) -> str:
        return f"{self.distro}-server-v1"


UBUNTU = DebSource("ubuntu", PACKAGE_VERSION, PACKAGE_SHA256, POLICY_RELEASE, PILOT_HOSTS)
UBUNTU_197 = DebSource(
    "ubuntu", "3.2.197-1ubuntu1",
    "1d30e147ef8e108a2b379ffffcfb765d66ddb24926974592b23d86e491a6d573",
    UUID("38c857b3-dab6-45f7-8b77-59edff8a9238"),
    {"192.168.100.12": "registoryengine", "192.168.100.45": "acti-v3"},
)
DEBIAN_PILOT = DebSource(
    "debian", "3.2.193-1deb12u1",
    "cc8ebf1da12d9f8106dd1ab627cd1517a3801c63c1315cf19524c54370b967fc",
    UUID("b41cf4eb-7b68-4350-83ba-cc42d4e35bd2"),
    {"10.83.1.11": "pve1"},
)
DEBIAN = DebSource(
    "debian", "3.2.194-1deb12u1",
    "a6345b2a4385b62965732f558d9f950df4f9beaf1e70ba75cf9c2a06d46317f1",
    UUID("06f879fc-a618-4ec2-8d9e-232cfe2662e5"),
    {"10.83.1.11": "pve1", "10.83.1.12": "pve2", "10.83.1.13": "pve3"},
)
DEB_SOURCES = {source.release_id: source for source in (UBUNTU, UBUNTU_197, DEBIAN_PILOT, DEBIAN)}


def is_deb_request(record: EnrollmentRequest) -> bool:
    return record.platform == "linux" and record.installer_release_id.startswith(("ubuntu-deb:", "debian-deb:"))


def validate_source(record: EnrollmentRequest) -> DebSource:
    source = DEB_SOURCES.get(record.installer_release_id)
    if (
        record.platform != "linux"
        or source is None
        or record.installer_version != source.version
        or source.hosts.get(record.source_address) != record.hostname
    ):
        raise EnrollmentDenied("Exact DEB source required")
    return source


def build_request(body: UbuntuDebRequest | DebianDebRequest, *, address, pepper: bytes, now: datetime):
    distro = "debian" if isinstance(body, DebianDebRequest) else "ubuntu"
    source = DEB_SOURCES.get(f"{distro}-deb:{body.package_version}")
    if (
        source is None
        or source.hosts.get(str(address)) != body.hostname
        or body.package_sha256 != source.sha256
    ):
        raise EnrollmentDenied("Exact DEB source required")
    selection = CampaignSelection(
        "waiting_approval", None, "MANUAL_POLICY", policy_id=source.policy_id,
        enrollment_mode="manual", source_network_match=True, release_match=True,
    )
    record = build_enrollment_request(
        installation_id=normalize_install_session_id(body.installation_id),
        hardware_fingerprint=body.hardware_fingerprint, request_capability=body.request_capability,
        source_address=address, installer_version=source.version, installer_release_id=source.release_id,
        hostname=body.hostname, selection=selection, pepper=pepper, now=now,
    )
    record.platform = "linux"
    record.expires_at = now + timedelta(minutes=20)
    return record, selection


def build_campaign(record: EnrollmentRequest, *, pepper: bytes, now: datetime):
    source = validate_source(record)
    if record.status != "waiting_approval" or record.selected_campaign_id is not None or now >= record.expires_at:
        raise EnrollmentDenied("DEB request is no longer waiting for approval")
    return issue_campaign(
        pepper, expires_at=record.expires_at, max_uses=1,
        allowed_cidrs=[f"{record.source_address}/32"], target_platform="linux",
        policy={"policy_id": source.policy_id, "enrollment_mode": "manual",
                "allowed_native_releases": [str(source.policy_release)]},
        label=record.hostname, site=f"{source.distro}-server", now=now,
    ).record


DEB_RESPONSES = {
    200: {"model": PreEnrollmentRequestStatusV1, "description": "Recovered the exact existing request"},
    409: {"description": "Source or request conflict"},
    429: {"description": "Request rate limited"},
}


@router.post("/ubuntu/requests", status_code=201, response_model=PreEnrollmentRequestStatusV1, responses=DEB_RESPONSES)
async def create_request(body: UbuntuDebRequest, request: Request, response: Response):
    return await _create_request(body, request, response)


@router.post("/debian/requests", status_code=201, response_model=PreEnrollmentRequestStatusV1, responses=DEB_RESPONSES)
async def create_debian_request(body: DebianDebRequest, request: Request, response: Response):
    return await _create_request(body, request, response)


async def _create_request(body: UbuntuDebRequest | DebianDebRequest, request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    now = datetime.now(UTC)
    pepper = request.app.state.settings.device_token_pepper
    try:
        candidate, selection = build_request(body, address=_source_address(request), pepper=pepper, now=now)
    except (EnrollmentDenied, ValueError):
        raise HTTPException(409, "Exact DEB source required") from None
    async with request.app.state.session_provider() as session:
        try:
            # Share the Linux intake lock so source, identity and rate checks agree.
            from .linux_request_routes import lock_linux_intake, project
            await lock_linux_intake(session)
            existing = await session.scalar(select(EnrollmentRequest).where(
                EnrollmentRequest.platform == "linux",
                EnrollmentRequest.installation_id_digest == candidate.installation_id_digest,
            ).order_by(EnrollmentRequest.created_at.desc()).limit(1))
            if existing is not None:
                if (
                    existing.installer_release_id != candidate.installer_release_id
                    or existing.source_address != candidate.source_address
                    or not request_capability_matches(body.request_capability, existing.request_capability_digest, pepper)
                    or not request_bindings_match(existing, installation_id=body.installation_id,
                                                  hardware_fingerprint=body.hardware_fingerprint, pepper=pepper)
                ):
                    raise HTTPException(409, "Enrollment request identity is already owned")
                response.status_code = 200
                return project(existing)
            outstanding = await session.scalar(select(EnrollmentRequest.id).where(
                EnrollmentRequest.source_address == candidate.source_address,
                EnrollmentRequest.installer_release_id.in_(tuple(DEB_SOURCES)),
                EnrollmentRequest.expires_at > now,
                EnrollmentRequest.status.in_(["waiting_approval", "approved", "claim_issued", "enrolling"]),
            ).limit(1))
            prior = await session.scalar(select(EnrollmentClaim.id).where(
                EnrollmentClaim.fingerprint_digest == hardware_fingerprint_digest(body.hardware_fingerprint, pepper),
                EnrollmentClaim.device_id.is_not(None),
            ).limit(1))
            if outstanding is not None or prior is not None:
                raise HTTPException(409, "An existing DEB request or device owns this host")
            recent = (await session.scalars(select(EnrollmentRequest).where(
                EnrollmentRequest.created_at >= now - timedelta(hours=1),
                EnrollmentRequest.source_address == candidate.source_address,
            ))).all()
            if enrollment_request_rate_limited(recent, candidate, now=now):
                raise HTTPException(429, "Enrollment request rate limited")
            await persist_enrollment_request(session, request=candidate, selection=selection,
                                             request_id=audit_request_id(request), now=now)
            await session.commit()
            return project(candidate)
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, "Enrollment request identity is already owned") from None
