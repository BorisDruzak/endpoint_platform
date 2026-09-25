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
    DeviceEvent,
    ContextFinding,
    ContextSnapshot,
)
from .devices import Device, DeviceCredential, DeviceInstance, DeviceSession
from .installer import WindowsSetupRelease
from endpoint_server.browser_sensor.models import BrowserSensorRelease
from .enrollment import (
    EnrollmentCampaign,
    EnrollmentClaim,
    EnrollmentEvent,
    EnrollmentRequest,
    EnrollmentRequestClaimEnvelope,
    EnrollmentRetryEnvelope,
)
from .operations import EndpointOperation, ModuleOperationStep, OperationEvidence
from .modules import (
    ModuleDefinition,
    ModuleLiveTest,
    ModuleValidationRun,
    ModuleVersion,
)
from .updates import UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget
from endpoint_server.policy.models import (
    PolicyApplication,
    PolicyAssignment,
    PolicyDefinition,
    PolicyDeviceState,
    PolicyVersion,
)
from endpoint_server.security.models import SecurityEvent

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
    "DeviceEvent",
    "ContextFinding",
    "ContextSnapshot",
    "Device",
    "DeviceCredential",
    "DeviceInstance",
    "DeviceSession",
    "EnrollmentCampaign",
    "EnrollmentClaim",
    "EnrollmentEvent",
    "EnrollmentRequest",
    "EnrollmentRequestClaimEnvelope",
    "EnrollmentRetryEnvelope",
    "EndpointOperation",
    "ModuleOperationStep",
    "OperationEvidence",
    "PolicyAssignment",
    "PolicyApplication",
    "PolicyDefinition",
    "PolicyDeviceState",
    "PolicyVersion",
    "ModuleDefinition",
    "ModuleLiveTest",
    "ModuleValidationRun",
    "ModuleVersion",
    "ServiceClient",
    "ServiceCredential",
    "SecurityEvent",
    "UpdateBuild",
    "UpdateReport",
    "UpdateRollout",
    "UpdateTarget",
    "WindowsSetupRelease",
    "BrowserSensorRelease",
]
