from datetime import UTC, datetime
from uuid import uuid4
import pytest
from pydantic import ValidationError
from endpoint_contracts.installation_lifecycle import InstallationEventV1, InstallationEventAckV1


def event_data(**changes):
    value = dict(schema_version='endpoint_installation_event_v1', device_id=str(uuid4()), event_id=str(uuid4()),
        generation_id=str(uuid4()), sequence=1, previous_event_id=None, action='installed', occurred_at=datetime.now(UTC).isoformat(),
        native=dict(version='3.2.177',product_code='{12345678-1234-1234-1234-123456789ABC}',source_revision='a'*40,msi_sha256='b'*64,exit_code=0),
        cleanup=dict(support='not_applicable',browser='not_applicable'))
    value.update(changes)
    return value


def test_roundtrip():
    event = InstallationEventV1.model_validate(event_data())
    assert InstallationEventV1.model_validate_json(event.model_dump_json()) == event


@pytest.mark.parametrize('changes', [dict(sequence=True),dict(sequence='1'),dict(sequence=0),dict(sequence=2147483648),
    dict(previous_event_id=str(uuid4())),dict(sequence=2),dict(occurred_at='2026-11-07T12:00:00'),dict(action='unknown'),dict(secret='token')])
def test_reject_invalid_event(changes):
    with pytest.raises(ValidationError):
        InstallationEventV1.model_validate(event_data(**changes))


@pytest.mark.parametrize('field,value', [('exit_code',False),('exit_code',3010),('product_code','{12345678-1234-1234-1234-123456789abc}'),('source_revision','a'*41)])
def test_reject_native_proof(field,value):
    data=event_data(); data['native'][field]=value
    with pytest.raises(ValidationError):
        InstallationEventV1.model_validate(data)
