"""Bounded CUPS metadata audit; no titles, user content or spool-file access."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
import logging
from threading import Event, Thread
from time import monotonic
from urllib.parse import unquote, urlsplit
from uuid import UUID, NAMESPACE_URL, uuid5

from pc_agent.security.print_projection import PrintJobFacts, project_print_job as _project
from . import cups

_LOG = logging.getLogger(__name__)


def ordered_job_ids(rows, first_id: int) -> list[int]:
    result = []
    for row in rows:
        value = row.get('job-id')
        if type(value) is not int or not first_id <= value < 2**31 or (result and value <= result[-1]):
            raise ValueError('CUPS_JOB_ORDER_INVALID')
        result.append(value)
    return result


def initial_job_cursor() -> int:
    """Walk only public job IDs; do not retrospectively audit old user jobs."""
    cursor, deadline = 0, monotonic() + 5
    for _ in range(64):
        if monotonic() > deadline:
            raise TimeoutError('CUPS_BASELINE_TIMEOUT')
        rows = cups.query(0x000A, ('job-id',), which_jobs='all', first_job_id=cursor + 1, allow_page=True)
        identifiers = ordered_job_ids(rows, cursor + 1)
        if identifiers:
            cursor = identifiers[-1]
        if len(rows) < cups.MAX_RECORDS:
            return cursor
    raise ValueError('CUPS_BASELINE_LIMIT')


@dataclass(frozen=True, slots=True)
class PrintFacts:
    job_id: int
    job_uuid: UUID
    created_at: datetime
    printer_name: str
    page_count: int | None
    copies: int | None


def job_facts(row: dict) -> PrintFacts:
    identifier, raw_uuid = row.get('job-id'), row.get('job-uuid')
    if type(identifier) is not int or not 1 <= identifier < 2**31 or not isinstance(raw_uuid, str) or not raw_uuid.startswith('urn:uuid:'):
        raise ValueError('CUPS_JOB_ID_INVALID')
    job_uuid = UUID(raw_uuid[9:])
    if raw_uuid[9:].lower() != str(job_uuid):
        raise ValueError('CUPS_JOB_UUID_INVALID')
    created = row.get('time-at-creation')
    if type(created) is not int or not 0 < created <= datetime.now(UTC).timestamp() + 300:
        raise ValueError('CUPS_JOB_TIME_INVALID')
    uri = row.get('job-printer-uri')
    if not isinstance(uri, str) or len(uri) > 512 or any(ord(char) < 32 for char in uri):
        raise ValueError('CUPS_PRINTER_ID_INVALID')
    parsed = urlsplit(uri)
    if (parsed.scheme not in {'ipp', 'ipps'} or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.query or parsed.fragment
        or parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError('CUPS_PRINTER_ID_INVALID')
    prefix, separator, queue = parsed.path[1:].partition('/')
    if prefix not in {'printers', 'classes'} or not separator or not queue or '/' in queue:
        raise ValueError('CUPS_PRINTER_ID_INVALID')
    name = unquote(queue, errors='strict')
    if not name or len(name) > 512:
        raise ValueError('CUPS_PRINTER_ID_INVALID')
    return PrintFacts(identifier, job_uuid, datetime.fromtimestamp(created, UTC), name,
                      row.get('job-impressions'), row.get('copies'))


def project_print_job(facts: PrintFacts, policy):
    return _project(PrintJobFacts(job_id=facts.job_id, printer_name=facts.printer_name,
                                 page_count=facts.page_count, copies=facts.copies), policy,
        occurred_at=facts.created_at, event_identifier=uuid5(NAMESPACE_URL, f'endpoint:linux:cups:{facts.job_uuid}'))


class PrintNotifications:
    """Poll a bounded ID page, retry failed persistence before advancing it."""

    def __init__(self, on_job, *, interval_seconds: float = 2):
        if interval_seconds <= 0:
            raise ValueError('invalid CUPS audit interval')
        self._on_job = on_job
        self._interval = interval_seconds
        self._stop = Event()
        self._thread = None
        self._healthy = False
        self._cursor = 0
        self._pending = deque()
        self.failed = 0

    @property
    def available(self):
        return bool(self._healthy and self._thread is not None and self._thread.is_alive() and not self._stop.is_set())

    def start(self):
        if self._thread is not None:
            raise RuntimeError('print source already started')
        self._cursor = None
        self._stop.clear()
        self._healthy = False
        self._thread = Thread(target=self._run, name='EndpointLinuxPrint', daemon=True)
        try:
            self._thread.start()
        except BaseException:
            self._thread = None
            self._healthy = False
            raise

    def poll_once(self):
        if self._cursor is None:
            self._cursor = initial_job_cursor()
            return
        if not self._pending:
            rows = cups.query(0x000A, cups.AUDIT_JOB_ATTRIBUTES, which_jobs='all',
                              first_job_id=self._cursor + 1, allow_page=True)
            ordered_job_ids(rows, self._cursor + 1)
            facts_page = [job_facts(row) for row in rows]
            self._pending.extend(facts_page)
        while self._pending and not self._stop.is_set():
            facts = self._pending[0]
            self._on_job(facts)
            self._cursor = facts.job_id
            self._pending.popleft()

    def _run(self):
        try:
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception:
                    if self._healthy:
                        _LOG.warning('Linux CUPS audit source is unavailable')
                    self._healthy = False
                    self.failed += 1
                else:
                    self._healthy = True
                if self._stop.wait(self._interval):
                    break
        finally:
            self._healthy = False

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            # Baseline acquisition has a five-second deadline and may finish
            # one final three-second CUPS request before observing it.
            self._thread.join(timeout=9)
            if self._thread.is_alive():
                raise TimeoutError('CUPS source did not stop')
            self._thread = None
        self._pending.clear()
