"""Root-owned Chromium policy files with conservative GPO conflict handling.

This adapter is stdlib-only so the RPM-owned privileged helper can load exactly
this file and the closed request protocol without loading the Agent runtime.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from pc_agent.browser_policy_protocol import _unique_object

APPROVED_UPDATE_URL = 'https://endpoint.sosnadmin.local/api/v1/browser-sensor/update.xml'
NATIVE_HOST = 'ru.sosnadmin.endpoint.browser'
OWNED_POLICY_NAME = '99-endpoint-browser-sensor.json'
POLICY_ROOTS = {'chromium': Path('/etc/chromium/policies/managed'),
                'chrome': Path('/etc/opt/chrome/policies/managed')}
STATE_ROOT = Path('/var/lib/endpoint-agent-browser-policy')
_BINARIES = {'chromium': ('/usr/bin/chromium', '/usr/bin/chromium-browser'),
             'chrome': ('/usr/bin/google-chrome', '/usr/bin/google-chrome-stable')}
_FOREIGN_EXTENSION_KEYS = ('ExtensionSettings', 'ExtensionInstallForcelist',
                           'ExtensionInstallBlocklist', 'ExtensionInstallAllowlist')


class BrowserPolicyConflict(RuntimeError):
    """Ownership or another corporate policy prevents this narrow change."""


def _directory(path: Path):
    if not path.is_absolute() or path.resolve() != path:
        raise BrowserPolicyConflict('POLICY_PATH_UNSAFE')
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise BrowserPolicyConflict('POLICY_DIRECTORY_UNSAFE')


def _read(path: Path) -> bytes | None:
    _directory(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
        or info.st_nlink != 1 or info.st_size > 65536):
        raise BrowserPolicyConflict('POLICY_FILE_UNSAFE')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        current = os.fstat(source.fileno())
        if (current.st_dev, current.st_ino, current.st_uid, current.st_mode, current.st_nlink) != (
                info.st_dev, info.st_ino, 0, info.st_mode, 1):
            raise BrowserPolicyConflict('POLICY_FILE_CHANGED')
        data = source.read(65537)
    if len(data) > 65536:
        raise BrowserPolicyConflict('POLICY_FILE_TOO_LARGE')
    return data


def _flush_directory(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create(path: Path, data: bytes):
    """Publish a complete file without replacing even a racing foreign file."""
    _directory(path.parent)
    temporary = path.parent / f'.endpoint-{uuid4().hex}.tmp'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            os.fchmod(target.fileno(), 0o644)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(path), 1):
            code = ctypes.get_errno()
            if code == errno.EEXIST:
                raise BrowserPolicyConflict('POLICY_TARGET_EXISTS')
            raise OSError(code, 'policy publication failed')
        _flush_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _json_bytes(document):
    return (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def _check_foreign(document):
    for name in _FOREIGN_EXTENSION_KEYS:
        if name in document:
            expected_type = dict if name == 'ExtensionSettings' else list
            if not isinstance(document[name], expected_type) or document[name]:
                raise BrowserPolicyConflict('POLICY_EXTERNAL_EXTENSION_SETTINGS')
    blocked, allowed = document.get('NativeMessagingBlocklist', []), document.get('NativeMessagingAllowlist', [])
    if not isinstance(blocked, list) or not isinstance(allowed, list):
        raise BrowserPolicyConflict('POLICY_NATIVE_HOST_CONFLICT')
    if (NATIVE_HOST in blocked or '*' in blocked) and NATIVE_HOST not in allowed:
        raise BrowserPolicyConflict('POLICY_NATIVE_HOST_CONFLICT')


class LinuxBrowserPolicy:
    def __init__(self, *, extension_id: str, roots=None, state_root: Path = STATE_ROOT, installed=None):
        if re.fullmatch(r'[a-p]{32}', extension_id) is None:
            raise ValueError('invalid pinned extension identity')
        self.extension_id = extension_id
        self.update_url = APPROVED_UPDATE_URL
        self.roots = dict(POLICY_ROOTS if roots is None else roots)
        if not set(self.roots) <= set(POLICY_ROOTS):
            raise ValueError('unsupported browser product')
        self.state_root = state_root
        self._installed = (set(installed) if installed is not None else
            {kind for kind, binaries in _BINARIES.items() if any(Path(binary).is_file() for binary in binaries)})
        self._payload = _json_bytes({'ExtensionSettings': {extension_id: {
            'installation_mode': 'force_installed', 'update_url': self.update_url}}})

    def _marker_path(self, kind):
        return self.state_root / f'{kind}.json'

    def _marker_bytes(self, kind):
        return _json_bytes({'schema_version': 1, 'product': kind, 'extension_id': self.extension_id,
                            'policy_sha256': hashlib.sha256(self._payload).hexdigest()})

    def _owned(self, kind):
        marker = _read(self._marker_path(kind))
        payload = _read(self.roots[kind] / OWNED_POLICY_NAME)
        if marker is not None and (marker != self._marker_bytes(kind) or payload not in (None, self._payload)):
            raise BrowserPolicyConflict('POLICY_OWNERSHIP_CONFLICT')
        return marker, payload

    def _foreign(self, kind):
        directory = self.roots[kind]
        _directory(directory)
        paths = sorted(path for path in directory.iterdir() if path.name.endswith('.json') and path.name != OWNED_POLICY_NAME)
        if len(paths) > 64:
            raise BrowserPolicyConflict('POLICY_FILE_LIMIT')
        result = []
        for path in paths:
            try:
                raw = _read(path)
                if raw is None:
                    raise BrowserPolicyConflict('POLICY_FILE_CHANGED')
                value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_object)
            except (ValueError, UnicodeError) as error:
                raise BrowserPolicyConflict('POLICY_JSON_INVALID') from error
            if not isinstance(value, dict):
                raise BrowserPolicyConflict('POLICY_JSON_INVALID')
            result.append(value)
        return result

    def apply(self, family):
        if family == 'yandex':
            # No Yandex paths are guessed. Absent Yandex needs no mutation.
            if Path('/usr/bin/yandex-browser').exists() or Path('/usr/bin/yandex_browser').exists():
                raise BrowserPolicyConflict('BROWSER_PATH_UNVERIFIED')
            return 'APPLIED'
        if family != 'chrome':
            raise ValueError('unsupported browser family')
        products = [kind for kind in self.roots if kind in self._installed]
        for kind in products:
            marker, payload = self._owned(kind)
            if marker is None and payload is not None:
                raise BrowserPolicyConflict('POLICY_EXTERNAL_OWNER')
            for document in self._foreign(kind):
                _check_foreign(document)
        for kind in products:
            marker, payload = self._owned(kind)
            if marker is None:
                _create(self._marker_path(kind), self._marker_bytes(kind))
            if payload is None:
                _create(self.roots[kind] / OWNED_POLICY_NAME, self._payload)
        return 'APPLIED'

    def relinquish(self, family):
        if family == 'yandex':
            return 'EXTERNALLY_MANAGED'
        if family != 'chrome':
            raise ValueError('unsupported browser family')
        for kind, directory in self.roots.items():
            if not directory.exists():
                continue
            marker, payload = self._owned(kind)
            if marker is None:
                continue
            if payload is not None:
                (directory / OWNED_POLICY_NAME).unlink()
                _flush_directory(directory)
            self._marker_path(kind).unlink()
            _flush_directory(self.state_root)
        return 'EXTERNALLY_MANAGED'

    def inspect(self, kind):
        try:
            marker, payload = self._owned(kind)
            documents = self._foreign(kind)
            if marker is not None:
                for document in documents:
                    _check_foreign(document)
                return ('ENDPOINT', 'APPLIED') if payload == self._payload else ('ENDPOINT', 'NOT_APPLIED')
            if payload is not None:
                if payload != self._payload:
                    return 'CONFLICT', 'CONFLICT'
                documents.append(json.loads(payload))
            found = False
            for document in documents:
                settings = document.get('ExtensionSettings', {})
                entries = document.get('ExtensionInstallForcelist', [])
                if not isinstance(settings, dict) or not isinstance(entries, list):
                    return 'CONFLICT', 'CONFLICT'
                if self.extension_id in settings:
                    entry = settings[self.extension_id]
                    if (not isinstance(entry, dict) or entry.get('installation_mode') != 'force_installed'
                        or entry.get('update_url') != self.update_url):
                        return 'CONFLICT', 'CONFLICT'
                    found = True
                for entry in entries:
                    if isinstance(entry, str) and entry.split(';', 1)[0] == self.extension_id:
                        if entry != self.extension_id + ';' + self.update_url:
                            return 'CONFLICT', 'CONFLICT'
                        found = True
            return ('EXTERNAL', 'APPLIED') if found else ('NONE', 'NOT_APPLIED')
        except BrowserPolicyConflict:
            return 'CONFLICT', 'CONFLICT'
        except OSError:
            return 'UNKNOWN', 'UNKNOWN'
