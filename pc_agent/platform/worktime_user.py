"""Credential-free per-user notification worker, shared by Windows and ALT."""
from __future__ import annotations

import os
from pathlib import Path
from threading import Lock, Thread
import webbrowser
from contextlib import suppress

from endpoint_contracts.worktime_companion import CompanionActionV1, CompanionPollV1, CompanionReplyV1


class UserCompanion:
    def __init__(self, exchange, notify, *, state_path=None, open_url=webbrowser.open):
        self.exchange, self.notify, self.open_url = exchange, notify, open_url
        root = Path(os.environ.get('LOCALAPPDATA') or os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state')
        self.state_path = state_path or root / 'EndpointAgent' / 'worktime-notifications.txt'
        self._lock = Lock()
        self._seen = set()

    def tick(self):
        if self._lock.acquire(blocking=False):
            try:
                Thread(target=self._run, name='EndpointWorkTimeNotice', daemon=True).start()
            except RuntimeError:
                self._lock.release()

    def _send(self, message):
        reply = self.exchange(message.model_dump_json().encode('utf-8'))
        return CompanionReplyV1.model_validate_json(reply)

    def _run(self):
        try:
            self.run_once()
        except Exception:
            pass  # Optional portal interactions never stop observation.
        finally:
            self._lock.release()

    def run_once(self):
        reply = self._send(CompanionPollV1())
        if reply.request_id is None or reply.lease_id is None:
            return
        identifier = str(reply.request_id)
        if self.state_path.exists():
            if self.state_path.stat().st_size > 1024 * 1024:
                return  # Bounded fail-closed local receipt read.
            self._seen.update(self.state_path.read_text(encoding='ascii').splitlines())
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        accepted = self._send(CompanionActionV1(request_id=reply.request_id,lease_id=reply.lease_id,action='present'))
        if accepted.request_id != reply.request_id or accepted.lease_id != reply.lease_id:
            return
        if identifier in self._seen:
            self._send(CompanionActionV1(request_id=reply.request_id,lease_id=reply.lease_id,action='displayed'))
            return
        # Mark before invoking the native surface, so process restart cannot spam.
        # No URL or identity is persisted. The server always reauthorizes actions.
        try:
            with self.state_path.open('a', encoding='ascii') as receipt:
                receipt.write(identifier + '\n')
                receipt.flush()
                os.fsync(receipt.fileno())
            self._seen.add(identifier)
            action = self.notify()
        except Exception:
            with suppress(Exception):
                self._send(CompanionActionV1(request_id=reply.request_id,lease_id=reply.lease_id,action='failed'))
            # A known native startup failure has displayed nothing. Release its
            # local receipt so the server lease can retry once the surface works.
            self._seen.discard(identifier)
            temporary = self.state_path.with_suffix('.tmp')
            temporary.write_text(''.join(item + '\n' for item in sorted(self._seen)), encoding='ascii')
            os.replace(temporary, self.state_path)
            raise
        self._send(CompanionActionV1(request_id=reply.request_id,lease_id=reply.lease_id,action='displayed'))
        if action not in {'reason', 'later'}:
            return
        authorized = self._send(CompanionActionV1(request_id=reply.request_id,lease_id=reply.lease_id,action=action))
        if (action == 'reason' and authorized.request_id == reply.request_id
                and authorized.lease_id == reply.lease_id and authorized.portal_url):
            self.open_url(authorized.portal_url)
