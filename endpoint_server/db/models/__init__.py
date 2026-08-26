"""Import all ownership models so their tables are registered with metadata."""

from .administration import (
    AdminSession,
    AdminUser,
    AuditEvent,
    ServiceClient,
    ServiceCredential,
)
from .commands import Command, CommandDelivery, CommandResult
from endpoint_server.context.models import (
    ContextCollection,
    ContextCurrent,
    ContextDiff,
    ContextFinding,
    ContextSnapshot,
)
from .devices import Device, DeviceCredential, DeviceInstance, DeviceSession
from .enrollment import (
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRetryEnvelope,
)
from .operations import EndpointOperation
from .modules import (
    ModuleDefinition,
    ModuleLiveTest,
    ModuleValidationRun,
    ModuleVersion,
)
from .updates import UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget

__all__ = [
    "AdminSession",
    "AdminUser",
    "AuditEvent",
    "Command",
    "CommandDelivery",
    "CommandResult",
    "ContextCollection",
    "ContextCurrent",
    "ContextDiff",
    "ContextFinding",
    "ContextSnapshot",
    "Device",
    "DeviceCredential",
    "DeviceInstance",
    "DeviceSession",
    "EnrollmentCampaign",
    "EnrollmentClaim",
    "EnrollmentEvent",
    "EnrollmentRetryEnvelope",
    "EndpointOperation",
    "ModuleDefinition",
    "ModuleLiveTest",
    "ModuleValidationRun",
    "ModuleVersion",
    "ServiceClient",
    "ServiceCredential",
    "UpdateBuild",
    "UpdateReport",
    "UpdateRollout",
    "UpdateTarget",
]
