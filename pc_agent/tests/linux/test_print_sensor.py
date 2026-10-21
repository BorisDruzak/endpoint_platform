"""CUPS audit reads job metadata only and retains deterministic job identity."""
from datetime import UTC, datetime
from uuid import uuid4
import struct

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.linux import cups
from pc_agent.platform.linux.print_sensor import PrintNotifications, job_facts, project_print_job, initial_job_cursor
from tests.contracts.test_endpoint_policy_v1 import _policy


def row(identifier=1, **changes):
    return {'job-id':identifier, 'job-uuid':f'urn:uuid:{uuid4()}',
            'time-at-creation':int(datetime.now(UTC).timestamp()),
            'job-printer-uri':'ipp://localhost/printers/Acceptance', 'job-state':4,
            'job-impressions':2, 'copies':1} | changes


def test_print_projection_does_not_copy_job_titles_owners_or_paths():
    raw = row(**{'job-name':'PRIVATE_DOCUMENT', 'job-originating-user-name':'unverified',
                  'document-name':'PRIVATE_PATH', 'job-k-octets':17})
    facts = job_facts(raw)
    event = project_print_job(facts, EndpointPolicyV1.model_validate(_policy()))
    assert event.event_type == 'PRINT_JOB' and event.safe_metadata.printer_identity == 'Acceptance'
    assert event.safe_metadata.page_count == 2 and event.safe_metadata.copies == 1
    assert event.safe_metadata.total_bytes is None and event.user_login is None
    assert event.event_identifier == project_print_job(job_facts(raw), EndpointPolicyV1.model_validate(_policy())).event_identifier
    assert 'PRIVATE_' not in event.model_dump_json() and 'unverified' not in event.model_dump_json()
    assert 'ipp://' not in event.model_dump_json()


@pytest.mark.parametrize('changes', [{'job-id':True}, {'job-uuid':'private'},
    {'time-at-creation':None}, {'job-printer-uri':'file:///private/document'},
    {'job-printer-uri':'ipp://secret@localhost/printers/Name'}])
def test_print_rejects_ambiguous_job_identity(changes):
    with pytest.raises(ValueError):
        job_facts(row(**changes))


def test_print_cursor_pages_past_old_history_without_reading_titles(monkeypatch):
    requested = []
    def query(operation, attrs, **options):
        assert operation == 0x000A and attrs == ('job-id',)
        requested.append(options['first_job_id'])
        first = options['first_job_id']
        return [{'job-id':value} for value in range(first, min(first + cups.MAX_RECORDS, 300))]
    monkeypatch.setattr(cups, 'query', query)
    assert initial_job_cursor() == 299
    assert requested == [1, 129, 257]


def test_print_cursor_rejects_a_server_ignoring_the_page_filter(monkeypatch):
    monkeypatch.setattr(cups, 'query', lambda *_args, **_kwargs: [{'job-id':1}] * cups.MAX_RECORDS)
    with pytest.raises(ValueError):
        initial_job_cursor()


def test_print_poll_retries_unpersisted_job_with_the_same_metadata(monkeypatch):
    raw = row(5)
    calls = []
    def query(_operation, attributes, **options):
        assert set(attributes) == set(cups.AUDIT_JOB_ATTRIBUTES)
        assert 'job-name' not in attributes and 'job-originating-user-name' not in attributes
        calls.append(options['first_job_id'])
        return [raw] if options['first_job_id'] <= 5 else []
    monkeypatch.setattr(cups, 'query', query)
    accepted = []
    def persist(facts):
        accepted.append(facts)
        if len(accepted) == 1:
            raise OSError('spool unavailable')
    source = PrintNotifications(persist)
    source._cursor = 4
    with pytest.raises(OSError):
        source.poll_once()
    raw['copies'] = 7
    source.poll_once()
    source.poll_once()
    assert accepted[0] is accepted[1] and accepted[1].copies == 1
    assert source._cursor == 5 and calls == [5, 6]


def test_invalid_page_does_not_partially_publish_earlier_rows(monkeypatch):
    monkeypatch.setattr(cups, 'query', lambda *_args, **_kwargs: [row(5), row(6, **{'job-uuid':'invalid'})])
    published = []
    source = PrintNotifications(published.append)
    source._cursor = 4
    with pytest.raises(ValueError):
        source.poll_once()
    assert not source._pending and not published and source._cursor == 4


def test_cups_audit_request_is_fixed_local_metadata_and_includes_cursor(monkeypatch):
    def attr(tag, name, value):
        key = name.encode(); raw = struct.pack('>i', value) if type(value) is int else value.encode()
        return bytes([tag]) + struct.pack('>H', len(key)) + key + struct.pack('>H', len(raw)) + raw
    response = (struct.pack('>BBHI', 1, 1, 0, 1) + b'\x02' + attr(0x21, 'job-id', 5)
        + attr(0x45, 'job-printer-uri', 'ipp://localhost/printers/Test')
        + attr(0x42, 'job-name', 'PRIVATE_DOCUMENT') + b'\x03')
    requests = []
    class Connection:
        def __init__(self, host, timeout):
            assert host == 'localhost' and timeout == 3
        def request(self, method, path, **kwargs):
            assert method == 'POST' and path == '/'
            requests.append(kwargs['body'])
        def getresponse(self):
            return self
        status = 200
        def getheader(self, *_args):
            return 'application/ipp'
        def read(self, count):
            assert count == cups.MAX_RESPONSE_BYTES + 1
            return response
        def close(self):
            pass
    monkeypatch.setattr(cups, '_LocalCupsConnection', Connection)
    rows = cups.query(0x000A, cups.AUDIT_JOB_ATTRIBUTES, which_jobs='all', first_job_id=5, allow_page=True)
    assert rows == [{'job-id':5, 'job-printer-uri':'ipp://localhost/printers/Test'}]
    assert b'first-job-id' in requests[0] and b'job-uuid' in requests[0]
    assert b'job-name' not in requests[0] and b'job-originating-user-name' not in requests[0]


@pytest.mark.parametrize('operation,options', [(0x4002, {'allow_page':True}),
    (0x000A, {'first_job_id':True, 'allow_page':True, 'which_jobs':'all'}),
    (0x000A, {'first_job_id':1}), (0x000A, {'allow_page':True})])
def test_cups_rejects_invalid_pagination_before_opening_socket(operation, options):
    with pytest.raises(ValueError):
        cups.query(operation, ('job-id',), **options)
