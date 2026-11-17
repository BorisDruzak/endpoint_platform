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
    ('installing', 'recovery_required'), ('recovery_required', 'verifying'),
])
def test_valid_update_transitions(old, new):
    validate_setup_transition(old, new)


@pytest.mark.parametrize('old,new', [
    ('installing', 'cancelled'), ('verifying', 'cancelled'),
    ('assigned', 'applied'), ('applied', 'installing'),
    ('rolled_back', 'installing'), ('blocked', 'installing'),
    ('cancelled', 'verified'), ('assigned', 'installing'),
    ('installing', 'blocked'), ('verifying', 'blocked'),
    ('installing', 'failed'), ('verifying', 'failed'), ('recovery_required', 'cancelled'),
])
def test_cancel_or_replay_cannot_cross_the_native_start_boundary(old, new):
    with pytest.raises(ValueError):
        validate_setup_transition(old, new)


def recovered_target_proof():
    return dict(foundation_version='3.2.168', core_version='3.2.168', source_revision='b' * 40,
                msi_sha256='c' * 64, native_phase='accepted', exit_code=21,
                native_verified=True, core_verified=True, provenance_verified=True, pending=False,
                services_verified=True, companions_restored=True,
                private=dict(credential=True, identity=True, origin=True, ca=True),
                soak=dict(duration_seconds=180, samples=6, sensor_count=1, sensor_cpu_percent_max=0,
                          services_stable=True, companions_stable=True, connected=True))


def test_recovered_target_keeps_failed_native_exit_instead_of_claiming_applied():
    report = SetupProgressV1(attempt_id=uuid4(), phase='failed',
                            safe_code='native_failed_target_recovered', proof=recovered_target_proof())
    assert report.phase == 'failed' and report.proof.exit_code == 21


@pytest.mark.parametrize('phase,code', [
    ('failed', None), ('failed', 'native_failed_source_verified'), ('failed', 'unrelated'),
    ('recovery_required', None), ('recovery_required', 'native_failed_target_recovered'),
    ('applied', 'native_failed_target_recovered'), ('verifying', 'native_failed_target_recovered'),
])
def test_recovered_target_proof_cannot_use_another_phase_or_diagnostic(phase, code):
    with pytest.raises(ValidationError):
        SetupProgressV1(attempt_id=uuid4(), phase=phase, safe_code=code, proof=recovered_target_proof())


@pytest.mark.parametrize('defect', [
    'missing', 'native-phase', 'exit-zero', 'native', 'core', 'provenance', 'pending',
    'services', 'companions', 'private', 'no-soak', 'duration', 'samples', 'sensor',
    'stable-services', 'stable-companions', 'connected',
])
def test_recovered_target_requires_healthy_real_active_sensor_soak(defect):
    evidence = recovered_target_proof()
    if defect == 'missing': evidence = None
    elif defect == 'native-phase': evidence['native_phase'] = 'unchanged'
    elif defect == 'exit-zero': evidence['exit_code'] = 0
    elif defect in ('native', 'core', 'provenance', 'services'):
        evidence[defect + '_verified'] = False
    elif defect == 'pending': evidence['pending'] = True
    elif defect == 'companions': evidence['companions_restored'] = False
    elif defect == 'private': evidence['private']['credential'] = False
    elif defect == 'no-soak': evidence['soak'] = None
    elif defect == 'duration': evidence['soak']['duration_seconds'] = 179
    elif defect == 'samples': evidence['soak']['samples'] = 5
    elif defect == 'sensor': evidence['soak']['sensor_count'] = 0
    elif defect == 'stable-services': evidence['soak']['services_stable'] = False
    elif defect == 'stable-companions': evidence['soak']['companions_stable'] = False
    elif defect == 'connected': evidence['soak']['connected'] = False
    with pytest.raises(ValidationError):
        SetupProgressV1(attempt_id=uuid4(), phase='failed',
                        safe_code='native_failed_target_recovered', proof=evidence)
