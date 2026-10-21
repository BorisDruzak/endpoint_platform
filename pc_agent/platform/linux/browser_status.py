"""Read-only installed-browser facts; the shared runtime owns compliance data."""
from __future__ import annotations
from datetime import datetime
import json
import os
from pathlib import Path
import stat

import psutil

from pc_agent.browser_status import BrowserHostFacts
from .browser_policy import LinuxBrowserPolicy, BrowserPolicyConflict, NATIVE_HOST, _directory, _read

_WRAPPER = Path('/usr/lib/endpoint-agent/browser-bridge')
_NATIVE_ROOTS = {'chromium':Path('/etc/chromium/native-messaging-hosts'),
                 'chrome':Path('/etc/opt/chrome/native-messaging-hosts')}
_EXECUTABLES = {'chromium':{'/usr/lib64/chromium/chromium', '/usr/lib/chromium/chromium'},
                'chrome':{'/opt/google/chrome/chrome'}}
_NAMES = {'chrome', 'chromium', 'chromium-browser', 'yandex_browser', 'yandex-browser'}


def _trusted_executable(value: str) -> bool:
    try:
        path = Path(value)
        _directory(path.parent)
        info = path.lstat()
        return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    except (OSError, BrowserPolicyConflict):
        return False


class LinuxBrowserProbe:
    def __init__(self, *, extension_id: str, installed=None, process_iter=None):
        self._policy = LinuxBrowserPolicy(extension_id=extension_id, installed=installed)
        self._extension_id = extension_id
        self._products = self._policy.installed_products
        self._process_iter = process_iter or psutil.process_iter

    def _native_host_state(self, kind):
        try:
            raw = _read(_NATIVE_ROOTS[kind] / (NATIVE_HOST + '.json'))
            wrapper = _read(_WRAPPER)
            if raw is None or len(raw) > 4096 or wrapper is None or not os.access(_WRAPPER, os.X_OK):
                return 'MISSING'
            document = json.loads(raw)
            if (not isinstance(document, dict) or document.get('name') != NATIVE_HOST
                or document.get('type') != 'stdio' or document.get('path') != _WRAPPER.as_posix()
                or document.get('allowed_origins') != [f'chrome-extension://{self._extension_id}/']):
                return 'MISSING'
            return 'READY'
        except FileNotFoundError:
            return 'MISSING'
        except (OSError, BrowserPolicyConflict):
            return 'UNKNOWN'
        except (UnicodeError, ValueError):
            return 'MISSING'

    def bridge_available(self) -> bool:
        return bool(self._products) and all(self._native_host_state(kind) == 'READY' for kind in self._products)

    def collect(self, *, observed_at: datetime):
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError('browser observation time must be timezone-aware')
        running, uncertain, failed = set(), set(), False
        try:
            for process in self._process_iter(attrs=['name','exe'], ad_value=None):
                name, executable = process.info.get('name'), process.info.get('exe')
                if name not in _NAMES:
                    continue
                products = {kind for kind, paths in _EXECUTABLES.items()
                    if isinstance(executable, str) and executable in paths and _trusted_executable(executable)}
                if products:
                    running.update(products)
                else:
                    uncertain.add('yandex' if name.startswith('yandex') else 'chrome')
        except (OSError, psutil.Error):
            failed = True
        installed = self._products
        products = installed & {'chromium','chrome'}
        owners = [self._policy.inspect(kind) for kind in sorted(products)]
        if any(owner[0] == 'CONFLICT' for owner in owners):
            owner, installation = 'CONFLICT','CONFLICT'
        elif owners and all(item == owners[0] for item in owners):
            owner, installation = owners[0]
        else:
            owner, installation = 'UNKNOWN','UNKNOWN'
        state = ('RUNNING' if running & {'chromium','chrome'} else
                 'UNKNOWN' if failed or 'chrome' in uncertain or not products else 'CLOSED')
        native = [self._native_host_state(kind) for kind in products]
        return {
            'chrome':BrowserHostFacts(
                browser_state='DETECTED' if products or running & {'chromium','chrome'} else 'UNKNOWN',
                running_state=state, policy_owner=owner, installation_policy_state=installation,
                native_host_state='READY' if native and all(item == 'READY' for item in native) else
                                  'MISSING' if 'MISSING' in native else 'UNKNOWN',
                last_running_at=observed_at if state == 'RUNNING' else None),
            # No unverified Yandex policy/native-host paths are inferred.
            'yandex':BrowserHostFacts(browser_state='UNKNOWN', running_state='UNKNOWN',
                policy_owner='UNKNOWN', installation_policy_state='UNKNOWN', native_host_state='UNKNOWN',
                last_running_at=None),
        }
