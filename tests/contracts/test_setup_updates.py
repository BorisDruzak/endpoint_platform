from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts.setup_updates import (
    SetupReleaseManifestV1, SetupProgressV1, validate_setup_transition,
)


@pytest.fixture
def release():
    return dict(schema_version='windows_setup_release_v1', release_identifier='windows-setup-158',
                version='3.2.158', artifact_name='EndpointAgentSetup-3.2.158-x64.exe',
                sha256='a' * 64, size=145929600, source_revision='b' * 40,
                msi_sha256='c' * 64, tray_sha256='d' * 64, sensor_sha256='e' * 64)


def test_signed_full_setup_manifest_has_its_own_wire_contract(release):
    value = SetupReleaseManifestV1.model_validate(release)
    assert value.version == '3.2.158'
    assert value.artifact_name.endswith('.exe')


@pytest.mark.parametrize('field,value', [
    ('artifact_name', '../Setup.exe'), ('artifact_name', 'Setup.zip'),
    ('artifact_name', 'C:\\Temp\\Setup.exe'), ('version', '3.2.158+unbound'),
    ('size', True), ('size', 0), ('size', 2**32), ('sha256', 'A' * 64),
    ('source_revision', 'x' * 40), ('msi_sha256', 'short'),
    ('artifact_url', 'https://foreign.example/Setup.exe'),
])
def test_unbound_or_unsafe_release_metadata_is_rejected(release, field, value):
    with pytest.raises(ValidationError):
        SetupReleaseManifestV1.model_validate({**release, field: value})


def test_completion_requires_native_proof_not_just_a_version():
    with pytest.raises(ValidationError):
        SetupProgressV1.model_validate(dict(attempt_id=str(uuid4()), phase='applied'))


def test_opaque_error_details_cannot_be_reported():
    with pytest.raises(ValidationError):
        SetupProgressV1.model_validate(dict(attempt_id=str(uuid4()), phase='failed',
                                           safe_code='Authorization: Bearer secret'))


@pytest.mark.parametrize('old,new', [
    ('assigned', 'downloading'), ('downloading', 'verified'),
    ('verified', 'installing'), ('installing', 'verifying'),
    ('verifying', 'applied'), ('installing', 'rolled_back'),
    ('assigned', 'cancelled'), ('verified', 'cancelled'),
    ('verified', 'already_current'), ('downloading', 'blocked'),
])
def test_valid_update_transitions(old, new):
    validate_setup_transition(old, new)


@pytest.mark.parametrize('old,new', [
    ('installing', 'cancelled'), ('verifying', 'cancelled'),
    ('assigned', 'applied'), ('applied', 'installing'),
    ('rolled_back', 'installing'), ('blocked', 'installing'),
    ('cancelled', 'verified'), ('assigned', 'installing'),
])
def test_cancel_or_replay_cannot_cross_the_native_start_boundary(old, new):
    with pytest.raises(ValueError):
        validate_setup_transition(old, new)
