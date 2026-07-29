"""Import all ownership models so their tables are registered with metadata."""

from .administration import (
    AdminSession,
    AdminUser,
    AuditEvent,
    ServiceClient,
    ServiceCredential,
)
from .commands import Command, CommandDelivery, CommandResult
from .devices import Device, DeviceCredential, DeviceInstance, DeviceSession
from .enrollment import (
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRetryEnvelope,
)
from .updates import UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget

__all__ = [
    "AdminSession",
    "AdminUser",
    "AuditEvent",
    "Command",
    "CommandDelivery",
    "CommandResult",
    "Device",
    "DeviceCredential",
    "DeviceInstance",
    "DeviceSession",
    "EnrollmentCampaign",
    "EnrollmentClaim",
    "EnrollmentEvent",
    "EnrollmentRetryEnvelope",
    "ServiceClient",
    "ServiceCredential",
    "UpdateBuild",
    "UpdateReport",
    "UpdateRollout",
    "UpdateTarget",
]
