"""One-time local Setup-client migration by the existing privileged Core verifier.

No application network request is made here. A vendor-signed, packaged client
can install only from the fixed enrolled verifier context; its separate task
defers while the existing Core/native transaction remains active.
"""
from __future__ import annotations

import ctypes
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID


def packaged_client() -> Path | None:
    if os.name != 'nt' or not getattr(sys, 'frozen', False):
        return None
    path = Path(sys._MEIPASS) / 'setup-updater' / 'EndpointSetupUpdater.ps1'
    return path if path.is_file() else None


def is_local_system() -> bool:
    if os.name != 'nt':
        return False
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
        return win32security.ConvertSidToStringSid(sid) == 'S-1-5-18'
    finally:
        token.Close()


def system_powershell() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer)):
        raise OSError('native system directory unavailable')
    return Path(buffer.value) / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'


def assert_fixed_verifier_context(settings) -> bool:
    from .update_paths import WindowsUpdatePaths
    from .update_transaction import _read_state
    from pc_agent.version import AGENT_VERSION
    paths = WindowsUpdatePaths.production()
    if (settings.install_root != paths.install_root or settings.data_root != paths.updates_root.parent
            or settings.ca_file != settings.data_root / 'endpoint-ca.crt'):
        raise ValueError('Setup bootstrap requires the fixed enrolled verifier context')
    if not paths.pending_path.exists():
        return False
    pending = _read_state(paths.pending_path, 16384)
    if pending.get('version') != AGENT_VERSION or pending.get('archive_type') != 'zip':
        raise ValueError('Setup bootstrap requires its existing Core assignment')
    operation = UUID(pending['operation_id'])
    if not operation.int or str(operation) != pending['operation_id']:
        raise ValueError('Setup bootstrap operation identity invalid')
    return True


def _existing_client_verified(asset: Path) -> bool:
    """An exact signed and scheduled client does not need another install."""
    import pywintypes
    import win32com.client
    from endpoint_contracts.runtime_payload import read_json
    from . import durable_state, installer_fence
    from .authenticode_timestamp import has_verified_timestamp
    from .native_setup_observer import _PUBLISHER, _assert_administrative_file, _verify_task
    from .update_paths import WindowsUpdatePaths

    paths = WindowsUpdatePaths.production()
    receipt = paths.updates_root.parent.parent.parent / 'EndpointPlatformSetupUpdates' / 'client.json'
    try:
        installer_fence.assert_state_security(receipt, secret=True)
        with receipt.open('rb') as stream:
            record = read_json(stream.read(4097), 4096)
        version = record['client_version']
        if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            return False
        target = paths.install_root.parent.parent / 'EndpointPlatformSetupUpdater' / version / asset.name
        _assert_administrative_file(target)
        with durable_state._pinned_copy_source(asset), durable_state._pinned_copy_source(target):
            with asset.open('rb') as stream:
                raw = stream.read(2 * 1024 * 1024 + 1)
            if (len(raw) > 2 * 1024 * 1024 or raw != target.read_bytes()
                    or record['script_sha256'] != hashlib.sha256(raw).hexdigest()
                    or f"$script:ClientVersion='{version}'" not in raw.decode('utf-8-sig').splitlines()
                    or not has_verified_timestamp(target, _PUBLISHER)):
                return False
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            _verify_task(scheduler.GetFolder('\\').GetTask('EndpointSetupUpdater'), target, system_powershell())
        return True
    except (OSError, ValueError, KeyError, TypeError, pywintypes.error):
        return False


def bootstrap_setup_client(settings) -> int:
    asset = packaged_client()
    if asset is None:
        return 0
    try:
        if not is_local_system():
            return 0
        authorized = assert_fixed_verifier_context(settings)
        if authorized is False:
            return 0
        if authorized is True and _existing_client_verified(asset):
            return 0
        # Trust only the already chain-valid, fixed vendor leaf. AllSigned stays
        # enabled, including domain policy; no arbitrary publisher/root is added.
        literal = str(asset).replace("'", "''")
        command = f"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$asset='{literal}'
$pin=[IO.File]::Open($asset,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {{
 $signature=Get-AuthenticodeSignature -LiteralPath $asset
 if($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate -or $signature.SignerCertificate.Thumbprint -cne '4D4C23389F5FF77BC4EB32044761019EAE8FB776'){{exit 21}}
 $store=[Security.Cryptography.X509Certificates.X509Store]::new('TrustedPublisher','LocalMachine')
 try {{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);if(!$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$signature.SignerCertificate.Thumbprint,$false).Count){{$store.Add($signature.SignerCertificate)}}}}finally{{$store.Close()}}
 & $asset -Mode Install
 exit $LASTEXITCODE
}}finally{{$pin.Dispose()}}
"""
        encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
        result = subprocess.run(
            [str(system_powershell()), '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden',
             '-ExecutionPolicy', 'AllSigned', '-EncodedCommand', encoded],
            shell=False, timeout=75, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=0x08000000 if os.name == 'nt' else 0,
        )
        return 0 if result.returncode == 0 else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return 1
