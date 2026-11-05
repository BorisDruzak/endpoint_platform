"""Full Windows Setup delivery is distinct from the historical Core archive API."""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, StringConstraints, model_validator, field_validator

from .base import ContractModelV1
from .updates import ArtifactNameV1, SafeCodeV1, Sha256V1, UpdateIdentifierV1

WindowsVersion = Annotated[str, StringConstraints(pattern=r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
SourceRevision = Annotated[str, StringConstraints(pattern=r'^[0-9a-f]{40}$')]

QUALIFIED_SETUP_CLIENT_VERSION = '1.0.6'
QUALIFIED_SETUP_CLIENT_VERSIONS = ('1.0.5', QUALIFIED_SETUP_CLIENT_VERSION)
LEGACY_SETUP_CLIENT_VERSION = '1.0.4'
ACTIVE_SETUP_PHASES = ('assigned', 'downloading', 'verified', 'installing', 'verifying', 'recovery_required')
TERMINAL_SETUP_PHASES = ('applied', 'failed', 'rolled_back', 'blocked', 'cancelled', 'already_current')
SetupPhase = Literal['assigned', 'downloading', 'verified', 'installing', 'verifying',
                     'applied', 'failed', 'rolled_back', 'blocked', 'cancelled', 'already_current', 'recovery_required']
_NEXT = {
    'assigned': {'downloading', 'cancelled', 'failed', 'blocked'},
    'downloading': {'verified', 'cancelled', 'failed', 'blocked'},
    'verified': {'installing', 'already_current', 'cancelled', 'failed', 'blocked'},
    'installing': {'verifying', 'rolled_back', 'recovery_required'},
    'verifying': {'applied', 'rolled_back', 'recovery_required'},
    'recovery_required': {'verifying', 'rolled_back', 'failed'},
}


def validate_setup_transition(current: str, new: str) -> None:
    if current != new and new not in _NEXT.get(current, ()):
        raise ValueError('setup update transition is not permitted')


class SetupReleaseManifestV1(ContractModelV1):
    schema_version: Literal['windows_setup_release_v1']
    release_identifier: UpdateIdentifierV1
    version: WindowsVersion
    artifact_name: ArtifactNameV1
    sha256: Sha256V1
    size: Annotated[int, Field(strict=True, gt=0, le=512 * 1024 * 1024)]
    source_revision: SourceRevision
    msi_sha256: Sha256V1
    tray_sha256: Sha256V1
    sensor_sha256: Sha256V1

    @model_validator(mode='after')
    def setup_executable(self):
        if not self.artifact_name.endswith('.exe'):
            raise ValueError('full Setup artifact must be an EXE')
        return self


class SetupPrivateProofV1(ContractModelV1):
    credential: Annotated[bool, Field(strict=True)]
    identity: Annotated[bool, Field(strict=True)]
    origin: Annotated[bool, Field(strict=True)]
    ca: Annotated[bool, Field(strict=True)]

    @property
    def preserved(self):
        return all((self.credential, self.identity, self.origin, self.ca))


class SetupSoakProofV1(ContractModelV1):
    duration_seconds: Annotated[float, Field(ge=180, le=3600, allow_inf_nan=False)]
    samples: Annotated[int, Field(strict=True, ge=6, le=120)]
    sensor_count: Annotated[int, Field(strict=True, ge=0, le=1024)]
    sensor_cpu_percent_max: Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
    services_stable: Annotated[bool, Field(strict=True)]
    companions_stable: Annotated[bool, Field(strict=True)]
    connected: Annotated[bool, Field(strict=True)]


class SetupNativeProofV1(ContractModelV1):
    foundation_version: WindowsVersion
    core_version: WindowsVersion
    source_revision: SourceRevision
    msi_sha256: Sha256V1
    native_phase: Literal['accepted', 'rolled-back', 'unchanged']
    exit_code: Annotated[int, Field(strict=True, ge=0, le=65535)] | None = None
    native_verified: Annotated[bool, Field(strict=True)]
    core_verified: Annotated[bool, Field(strict=True)]
    provenance_verified: Annotated[bool, Field(strict=True)]
    pending: Annotated[bool, Field(strict=True)]
    services_verified: Annotated[bool, Field(strict=True)]
    companions_restored: Annotated[bool, Field(strict=True)]
    private: SetupPrivateProofV1
    soak: SetupSoakProofV1 | None = None

    @property
    def healthy(self):
        return (self.native_verified and self.core_verified and self.provenance_verified
                and not self.pending and self.services_verified and self.companions_restored
                and self.private.preserved)


class SetupProgressV1(ContractModelV1):
    attempt_id: UUID
    phase: Literal['downloading', 'verified', 'installing', 'verifying', 'already_current',
                   'applied', 'failed', 'rolled_back', 'blocked', 'recovery_required']
    safe_code: SafeCodeV1 | None = None
    proof: SetupNativeProofV1 | None = None

    @field_validator('safe_code', mode='before')
    @classmethod
    def empty_optional_diagnostic(cls, value):
        # Windows PowerShell's optional [string] parameter serializes its null
        # default as "". Both wire forms mean no diagnostic; nonempty codes
        # still pass the unchanged closed safe-code validation.
        return None if value == '' else value

    @model_validator(mode='after')
    def require_real_completion(self):
        if self.phase == 'failed' and self.proof is not None:
            if (not self.proof.healthy or self.proof.native_phase != 'unchanged'
                    or self.proof.exit_code != 21 or self.proof.soak is None
                    or not self.proof.soak.services_stable
                    or not self.proof.soak.companions_stable or not self.proof.soak.connected):
                raise ValueError('verified unchanged source after native rejection required')
        if self.phase in ('applied', 'rolled_back', 'already_current'):
            if self.proof is None or not self.proof.healthy:
                raise ValueError('healthy native proof is required')
            expected = {'applied': ('accepted', 0), 'rolled_back': ('rolled-back', 67),
                        'already_current': ('unchanged', None)}[self.phase]
            if (self.proof.native_phase, self.proof.exit_code) != expected:
                raise ValueError('native outcome differs from reported phase')
            if self.phase == 'applied' and (self.proof.soak is None or not self.proof.soak.services_stable or not self.proof.soak.companions_stable or not self.proof.soak.connected):
                raise ValueError('post-install stable observation is required')
        return self


class SetupClientHelloV1(ContractModelV1):
    client_version: Annotated[str, StringConstraints(pattern=r'^1\.0\.[0-9]+$')]
    foundation_version: WindowsVersion | None = None
    core_version: WindowsVersion | None = None
    ready: Annotated[bool, Field(strict=True)]
    safe_code: SafeCodeV1 | None = None


class SetupAssignmentRequestV1(ContractModelV1):
    release_id: UUID
    device_id: UUID
    reason: Annotated[str, StringConstraints(min_length=1, max_length=256)]


class SetupRecommendationV1(ContractModelV1):
    schema_version: Literal['windows_setup_recommendation_v1'] = 'windows_setup_recommendation_v1'
    assignment_id: UUID
    device_id: UUID
    release: SetupReleaseManifestV1

