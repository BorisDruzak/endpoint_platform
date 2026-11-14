"""Small local-only boundary around OS files and a fixed command allowlist."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from contextvars import ContextVar
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time

import aiohttp
import psutil

from .server_health import ROLES


MAX_PROBE_BYTES = 65_536
WINDOWS_INVENTORY_TIMEOUT_SECONDS = 8.0
_HTTP_PROBE_TIMEOUT = 2.0
TERMINATION_GRACE_SECONDS = 0.2
_DRAIN_JOIN_GRACE_SECONDS = 0.2
IN_OWNED_COMMAND_WORKER = ContextVar("IN_OWNED_COMMAND_WORKER", default=False)

LSBLK_COMMAND = ("lsblk", "--bytes", "--json", "--output", "NAME,MODEL,SIZE,WWN,SERIAL,ROTA,TRAN,TYPE")
IP_LINK_COMMAND = ("ip", "-json", "link", "show")
IP_DEFAULT_ROUTE_COMMAND = ("ip", "-json", "route", "show", "default")
IP_ADDRESS_COMMAND = ("ip", "-json", "address", "show")
SSHD_STATUS_COMMAND = ("systemctl", "is-active", "sshd")
NETWORK_MANAGER_STATUS_COMMAND = ("systemctl", "is-active", "NetworkManager")
UPDATE_SERVICE_STATUS_COMMAND = ("systemctl", "show", "--property=LoadState,ActiveState", "--", "endpoint-agent-update.service")
UPDATE_PATH_STATUS_COMMAND = ("systemctl", "show", "--property=LoadState,ActiveState", "--", "endpoint-agent-update.path")
PROCESS_COMMAND = ("ps", "-eo", "comm=,stat=")
JOURNAL_COMMAND = (
    "journalctl", "--system", "--lines=32", "--no-pager", "--output=json",
    "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,_TRANSPORT",
    "--since=-60min", "--priority=0..4",
)
WINDOWS_TASKLIST_COMMAND = ("tasklist", "/FO", "CSV", "/NH")
WHO_COMMAND = ("who",)
# Invoke the native session tool directly: query.exe can return its own nonzero
# dispatcher status even when quser.exe successfully returns interactive rows.
WINDOWS_QUERY_USER_COMMAND = ("quser",)
OPENVPN_UDP_PORT = 1194
OPENVPN_SOCKET_COMMAND = ("ss", "-H", "-l", "-u", "-n", "sport", "=", f":{OPENVPN_UDP_PORT}")
WINDOWS_NETWORK_COMMAND = (
    "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
    "$n=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'|ForEach-Object{[pscustomobject]@{name=$_.Description;mac=$_.MACAddress;ipv4=@($_.IPAddress|Where-Object{$_ -match '^\\d+\\.'});ipv6=@($_.IPAddress|Where-Object{$_ -match ':'});index=[int]$_.InterfaceIndex;link_type='ethernet';operational_state='unknown'}});$r=Get-CimInstance Win32_IP4RouteTable -Filter \"Destination='0.0.0.0' AND Mask='0.0.0.0'\"|Sort-Object Metric1|Select-Object -First 1;[pscustomobject]@{interfaces=$n;default_interface_index=if($r){[int]$r.InterfaceIndex}else{$null};default_gateway=if($r){$r.NextHop}else{$null}}|ConvertTo-Json -Depth 5 -Compress",
)
WINDOWS_PHYSICAL_STORAGE_COMMAND = (
    "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
    "$items=@(Get-PhysicalDisk -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{serial=$_.SerialNumber;model=$_.FriendlyName;size_bytes=[int64]$_.Size;media_type=[string]$_.MediaType;bus_type=[string]$_.BusType}});ConvertTo-Json -InputObject @($items) -Depth 3 -Compress",
)
WINDOWS_INVENTORY_COMMAND = (
    "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
    "$cs=Get-CimInstance Win32_ComputerSystem;$p=Get-CimInstance Win32_ComputerSystemProduct;$b=Get-CimInstance Win32_BIOS;$bb=Get-CimInstance Win32_BaseBoard;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;$m=Get-CimInstance Win32_PhysicalMemory;$d=Get-CimInstance Win32_DiskDrive|ForEach-Object{[pscustomobject]@{serial=$_.SerialNumber;model=$_.Model;size_bytes=[int64]$_.Size;media_type='UNKNOWN';bus_type=if($_.InterfaceType -eq 'SCSI'){'SAS'}elseif($_.InterfaceType -eq 'USB'){'USB'}elseif($_.InterfaceType -eq 'IDE'){'SATA'}else{'UNKNOWN'}}};$n=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'|ForEach-Object{[pscustomobject]@{name=$_.Description;mac=$_.MACAddress;ipv4=@($_.IPAddress|Where-Object{$_ -match '^\\d+\\.'});ipv6=@($_.IPAddress|Where-Object{$_ -match ':'});link_type='ethernet';operational_state='unknown'}};$ram=@($m|ForEach-Object{[pscustomobject]@{slot=$_.DeviceLocator;manufacturer=$_.Manufacturer;part_number=$_.PartNumber;serial=$_.SerialNumber;capacity_bytes=[int64]$_.Capacity;speed_mt_s=[int]$_.ConfiguredClockSpeed;memory_type=switch([int]$_.SMBIOSMemoryType){20{'DDR'}21{'DDR2'}24{'DDR3'}26{'DDR4'}34{'DDR5'}default{'UNKNOWN'}}}});[pscustomobject]@{system=@{hostname=$env:COMPUTERNAME;os_name='Windows';os_version=[System.Environment]::OSVersion.Version.ToString();os_build=[System.Environment]::OSVersion.Version.Build.ToString();architecture=if([Environment]::Is64BitOperatingSystem){'x86_64'}else{'x86_64'}};hardware=@{manufacturer=$cs.Manufacturer;model=$cs.Model;serial_number=$p.IdentifyingNumber;product_uuid=$p.UUID;cpu_model=$cpu.Name;bios_vendor=$b.Manufacturer;bios_version=$b.SMBIOSBIOSVersion;baseboard_manufacturer=$bb.Manufacturer;baseboard_model=$bb.Product;baseboard_serial=$bb.SerialNumber};memory=@{total_bytes=[int64]$cs.TotalPhysicalMemory;memory_type=$null;modules=$ram};storage=@($d);interfaces=@($n)}|ConvertTo-Json -Depth 6 -Compress",
)

_ALLOWED_COMMANDS = frozenset(
    {
        LSBLK_COMMAND,
        IP_LINK_COMMAND,
        IP_DEFAULT_ROUTE_COMMAND,
        IP_ADDRESS_COMMAND,
        SSHD_STATUS_COMMAND,
        NETWORK_MANAGER_STATUS_COMMAND,
        UPDATE_SERVICE_STATUS_COMMAND,
        UPDATE_PATH_STATUS_COMMAND,
        PROCESS_COMMAND,
        JOURNAL_COMMAND,
        WINDOWS_TASKLIST_COMMAND,
        WHO_COMMAND,
        WINDOWS_QUERY_USER_COMMAND,
        WINDOWS_NETWORK_COMMAND,
        WINDOWS_PHYSICAL_STORAGE_COMMAND,
        WINDOWS_INVENTORY_COMMAND,
        OPENVPN_SOCKET_COMMAND,
    }
)

_SERVER_SERVICE_COMMANDS = {
    unit: ("systemctl", "show", "--property=LoadState,ActiveState,SubState", "--no-pager", "--", unit)
    for role in ROLES.values()
    if role.platform == "linux"
    for unit in role.services
}
_ALLOWED_COMMANDS |= frozenset(_SERVER_SERVICE_COMMANDS.values())
_SERVER_VOLUMES = frozenset(volume.mount for role in ROLES.values() for volume in role.volumes)


class SystemProbe:
    """Permit only bounded reads and explicitly enumerated local commands."""

    @property
    def platform_name(self) -> str:
        return "windows" if os.name == "nt" else "linux"

    def windows_updater_status(self) -> str:
        try:
            state = psutil.win_service_get("EndpointAgentUpdater").status()
        except (OSError, psutil.Error):
            return "unknown"
        return {"running": "active", "stopped": "inactive"}.get(state, "unknown")

    def server_service_state(self, name: str) -> str:
        if os.name == "nt":
            try:
                return psutil.win_service_get(name).status()
            except psutil.NoSuchProcess:
                return "missing"
        output = self.run(_SERVER_SERVICE_COMMANDS[name], 2.0, 512)
        fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if fields.get("LoadState") == "not-found":
            return "missing"
        active, sub = fields.get("ActiveState"), fields.get("SubState")
        return f"{active}/{sub}" if active and sub else "unknown"

    def server_local_mounts(self) -> set[str]:
        if os.name == "nt":
            import ctypes

            # DRIVE_FIXED (3) excludes mapped, removable and unavailable drives.
            return {
                mount for mount in _SERVER_VOLUMES
                if len(mount) == 3 and mount[1:] == ":\\"
                and ctypes.windll.kernel32.GetDriveTypeW(mount) == 3
            }
        return {
            part.mountpoint for part in psutil.disk_partitions(all=False)
            if part.mountpoint in _SERVER_VOLUMES
            and (part.device.startswith("/dev/") or part.fstype == "zfs")
        }

    def server_disk_usage(self, mount: str):
        if mount not in _SERVER_VOLUMES:
            raise ValueError("unknown server mount")
        return psutil.disk_usage(mount)

    def server_http_status(self, port: int, path: str) -> int:
        return asyncio.run(_server_http_status(port, path))

    def acti_https_status(self, check: str) -> int:
        if check not in ("live", "ready"):
            raise ValueError("unknown ACTI health check")
        tls = ssl.create_default_context(cafile="/etc/endpoint-agent-ubuntu/acti-ca.crt")
        return asyncio.run(_server_http_status(443, f"/api/v1/health/{check}", tls=tls))

    def proxmox_health_snapshot(self) -> dict:
        with Path("/run/endpoint-proxmox-health/status.json").open("rb") as stream:
            data = stream.read(8193)
        if len(data) > 8192:
            raise ValueError("oversized Proxmox health snapshot")
        snapshot = json.loads(data)
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
            raise ValueError("invalid Proxmox health snapshot")
        sampled_at = snapshot.get("sampled_at")
        if type(sampled_at) is not int or not 0 <= time.time() - sampled_at <= 180:
            raise ValueError("stale Proxmox health snapshot")
        return snapshot

    def server_udp_listener(self, port: int) -> bool:
        if port != OPENVPN_UDP_PORT:
            raise ValueError("unknown server UDP listener")
        output = self.run(OPENVPN_SOCKET_COMMAND, 2.0, 4096, check_exit=True)
        return any(line.startswith("UNCONN ") for line in output.splitlines())

    def server_tcp_listener(self, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2.0):
                return True
        except ConnectionRefusedError:
            return False

    def server_has_disk_shares(self) -> bool:
        import ctypes
        from ctypes import wintypes

        class ShareInfo(ctypes.Structure):
            _fields_ = [("name", wintypes.LPWSTR), ("kind", wintypes.DWORD), ("remark", wintypes.LPWSTR)]

        netapi = ctypes.WinDLL("netapi32")
        shares = ctypes.POINTER(ShareInfo)()
        count = wintypes.DWORD()
        total = wintypes.DWORD()
        status = netapi.NetShareEnum(
            None, 1, ctypes.byref(shares), 16_384, ctypes.byref(count), ctypes.byref(total), None,
        )
        try:
            if status in (0, 234) and any(shares[index].kind == 0 for index in range(count.value)):
                return True
            if status != 0:
                raise OSError(status, "Unable to enumerate local SMB disk shares")
            return False
        finally:
            if shares:
                netapi.NetApiBufferFree(shares)

    def server_postgresql_ready(self) -> bool:
        try:
            result = subprocess.run(
                ("/usr/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432",
                 "-U", "postgres", "-d", "postgres", "-t", "2", "-q"),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "PGPASSFILE": "/dev/null"},
                timeout=3, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("PostgreSQL readiness probe exceeded its deadline") from error
        if result.returncode not in (0, 1, 2):
            raise ValueError("PostgreSQL readiness check did not run")
        return result.returncode == 0

    def windows_system(self) -> dict[str, object]:
        from pc_agent.platform.windows.identity import native_system

        return native_system()

    def windows_hardware(self) -> dict[str, object]:
        from pc_agent.platform.windows.identity import native_hardware

        return native_hardware()

    def windows_health(self) -> dict[str, int]:
        from pc_agent.platform.windows.identity import native_health

        return native_health()

    def windows_storage(self) -> list[dict[str, object]]:
        from pc_agent.platform.windows.storage import native_storage

        return native_storage()

    def windows_interfaces(self) -> list[dict[str, object]]:
        value = self._windows_network()
        records = value.get("interfaces") if isinstance(value.get("interfaces"), list) else []
        result: list[dict[str, object]] = []
        for item in records:
            if not isinstance(item, dict):
                continue
            ipv4 = item.get("ipv4") if isinstance(item.get("ipv4"), list) else []
            ipv6 = item.get("ipv6") if isinstance(item.get("ipv6"), list) else []
            result.append({
                "name": item.get("name"), "mac": item.get("mac"),
                "link_type": item.get("link_type"),
                "operational_state": item.get("operational_state"),
                "addresses": [*ipv4, *ipv6],
            })
        return result

    def windows_default_route(self) -> dict[str, str | None]:
        value = self._windows_network()
        index = value.get("default_interface_index")
        interfaces = value.get("interfaces") if isinstance(value.get("interfaces"), list) else []
        name = next(
            (
                str(item.get("name"))
                for item in interfaces
                if isinstance(item, dict) and item.get("index") == index and item.get("name")
            ),
            "unknown",
        )
        gateway = value.get("default_gateway")
        return {"interface": name, "gateway": str(gateway) if gateway else None}

    def windows_inventory(self) -> dict[str, object]:
        """Read one fixed local CIM inventory projection on Windows only."""
        if os.name != "nt":
            return {}
        import json
        try:
            value = json.loads(
                self.run(WINDOWS_INVENTORY_COMMAND, WINDOWS_INVENTORY_TIMEOUT_SECONDS, MAX_PROBE_BYTES)
            )
        except (OSError, ValueError, TimeoutError):
            return {}
        if not isinstance(value, dict):
            return {}
        try:
            details = json.loads(
                self.run(WINDOWS_PHYSICAL_STORAGE_COMMAND, 5.0, MAX_PROBE_BYTES)
            )
        except (OSError, ValueError, TimeoutError):
            details = []
        return {
            **value,
            "storage_details": details if isinstance(details, list) else [],
        }

    def _windows_network(self) -> dict[str, object]:
        if os.name != "nt":
            return {}
        import json
        try:
            value = json.loads(self.run(WINDOWS_NETWORK_COMMAND, 5.0, MAX_PROBE_BYTES))
        except (OSError, ValueError, TimeoutError):
            return {}
        return value if isinstance(value, dict) else {}

    def session_info(self) -> dict[str, object]:
        """Read a bounded OS-reported interactive session, never credentials."""
        if os.name != "nt":
            from pc_agent.platform.linux.sessions import list_sessions
            try:
                sessions = list_sessions()
            except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
                return {}
            selected = next((session for session in sessions if session.active), None)
            return {
                "current_user_login": selected.user_login if selected else None,
                "interactive_session_present": selected is not None,
            }
        command = WINDOWS_QUERY_USER_COMMAND
        try:
            output = self.run(command, 2.0, 8192)
        except (OSError, ValueError, TimeoutError):
            return {}
        for line in output.splitlines():
            fields = line.lstrip("> ").split()
            if not fields or fields[0].upper() in {"USERNAME", "USER"}:
                continue
            if command == WINDOWS_QUERY_USER_COMMAND:
                # query user can omit SESSIONNAME, but a genuine user row
                # always has a numeric session ID followed by state/time.
                # Headers are localized; service session zero is not a user.
                id_index = 1 if len(fields) >= 4 and fields[1].isascii() and fields[1].isdigit() else 2
                if (
                    len(fields) < id_index + 3
                    or not fields[id_index].isascii()
                    or not fields[id_index].isdigit()
                    or int(fields[id_index]) == 0
                ):
                    continue
            return {"current_user_login": fields[0][:256], "interactive_session_present": True}
        return {"current_user_login": None, "interactive_session_present": False}

    def read_text(self, path: str, max_bytes: int) -> str:
        limit = _bounded_limit(max_bytes)
        with Path(path).open("rb") as source:
            return source.read(limit).decode("utf-8", errors="replace")

    def run(
        self, argv: Sequence[str], timeout_seconds: float, max_bytes: int, *, check_exit: bool = False,
    ) -> str:
        command = tuple(str(item) for item in argv)
        if command not in _ALLOWED_COMMANDS:
            raise ValueError("context probe command is not allowlisted")
        if timeout_seconds <= 0 or timeout_seconds > 10:
            raise ValueError("context probe timeout must be between 0 and 10 seconds")
        limit = _bounded_limit(max_bytes)
        executable = shutil.which(command[0])
        if not executable:
            raise FileNotFoundError(command[0])
        try:
            output = _execute_bounded_command(
                (executable, *command[1:]), timeout_seconds, limit, check_exit=check_exit or command in {WINDOWS_QUERY_USER_COMMAND, JOURNAL_COMMAND},
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("context probe command timed out") from exc
        if command == WINDOWS_QUERY_USER_COMMAND and os.name == "nt":
            return output.decode("oem", errors="strict")
        return output.decode("utf-8", errors="replace")


async def _server_http_status(port: int, path: str, *, tls: ssl.SSLContext | None = None) -> int:
    timeout = aiohttp.ClientTimeout(total=_HTTP_PROBE_TIMEOUT)
    scheme = "https" if tls is not None else "http"
    options = {"ssl": tls, "server_hostname": "localhost", "headers": {"Host": "localhost"}} if tls else {}
    try:
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(f"{scheme}://127.0.0.1:{port}{path}", allow_redirects=False, **options) as response:
                return response.status
    except aiohttp.ClientSSLError as error:
        raise ssl.SSLError("local HTTPS certificate verification failed") from error
    except aiohttp.ClientConnectorError as error:
        raise error.os_error from error
    except aiohttp.ClientError as error:
        raise ValueError("invalid local HTTP response") from error


def _bounded_limit(max_bytes: int) -> int:
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("context probe max_bytes must be a positive integer")
    return min(max_bytes, MAX_PROBE_BYTES)


def _execute_bounded_command(
    command: tuple[str, ...], timeout_seconds: float, limit: int, *,
    check_exit: bool = False,
) -> bytes:
    """Capture local command output without materializing unbounded pipe streams."""
    popen_options: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    # The outer owner must retain every fixed probe in its process group.
    own_process_group = os.name == "posix" and not IN_OWNED_COMMAND_WORKER.get()
    if own_process_group:
        popen_options["start_new_session"] = True
    process = subprocess.Popen(command, **popen_options)
    assert process.stdout is not None
    assert process.stderr is not None
    stdout = _BoundedDrain(process.stdout, limit)
    stderr = _BoundedDrain(process.stderr, limit)
    stdout.start()
    stderr.start()

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    cleanup_failed = False
    cleanup_attempted = False
    try:
        while process.poll() is None:
            if stdout.full.is_set() or stderr.full.is_set() or time.monotonic() >= deadline:
                timed_out = time.monotonic() >= deadline
                cleanup_attempted = True
                cleanup_failed = not _terminate_and_reap(process, own_process_group=own_process_group)
                break
            time.sleep(0.01)
    finally:
        if not cleanup_attempted and process.poll() is None:
            cleanup_failed = not _terminate_and_reap(process, own_process_group=own_process_group) or cleanup_failed
        elif not cleanup_attempted and not _wait_for_exit(process):
            cleanup_failed = True
        stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
        stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
        if stdout.is_alive() or stderr.is_alive():
            timed_out = True
            cleanup_failed = (
                not own_process_group
                or not _terminate_pipe_holding_group(process, stdout, stderr)
                or cleanup_failed
            )

    if timed_out or cleanup_failed:
        raise subprocess.TimeoutExpired(command, timeout_seconds)
    if check_exit:
        if stdout.full.is_set() or stderr.full.is_set():
            raise ValueError("fixed command output exceeds bound")
        if process.returncode != 0:
            raise OSError("fixed command failed")
        return bytes(stdout.output)
    return (bytes(stdout.output) + bytes(stderr.output))[:limit]


def _terminate_and_reap(
    process: subprocess.Popen[bytes], *, own_process_group: bool,
) -> bool:
    """Stop a child without letting a hung exit path block a collector."""
    if process.poll() is not None:
        return _wait_for_exit(process)
    if not _signal_process(process, terminate=True, own_process_group=own_process_group):
        return _wait_for_exit(process)
    if _wait_for_exit(process):
        return True
    if not _signal_process(process, terminate=False, own_process_group=own_process_group):
        return _wait_for_exit(process)
    return _wait_for_exit(process)


def _signal_process(
    process: subprocess.Popen[bytes], *, terminate: bool, own_process_group: bool = True,
) -> bool:
    """Signal a process group where supported, without leaking OS cleanup errors."""
    if os.name == "posix" and own_process_group:
        try:
            os.killpg(process.pid, signal.SIGTERM if terminate else signal.SIGKILL)
        except AttributeError:
            pass
        except ProcessLookupError:
            return False
        except OSError:
            return False
        else:
            return True

    try:
        if terminate:
            process.terminate()
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        return False
    return True


def _wait_for_exit(process: subprocess.Popen[bytes]) -> bool:
    try:
        process.wait(timeout=TERMINATION_GRACE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _terminate_pipe_holding_group(
    process: subprocess.Popen[bytes], stdout: _BoundedDrain, stderr: _BoundedDrain
) -> bool:
    """Stop POSIX descendants that retain probe pipes after their parent exits."""
    if os.name != "posix":
        return False
    if not _signal_process(process, terminate=True):
        return False
    _wait_for_exit(process)
    stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
    stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
    if not stdout.is_alive() and not stderr.is_alive():
        return True
    if not _signal_process(process, terminate=False):
        return False
    _wait_for_exit(process)
    stdout.join(_DRAIN_JOIN_GRACE_SECONDS)
    stderr.join(_DRAIN_JOIN_GRACE_SECONDS)
    return not stdout.is_alive() and not stderr.is_alive()


class _BoundedDrain:
    def __init__(self, stream: object, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.output = bytearray()
        self.full = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout_seconds: float) -> None:
        self._thread.join(timeout=timeout_seconds)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _drain(self) -> None:
        try:
            while len(self.output) < self._limit:
                chunk = self._stream.read(min(8192, self._limit - len(self.output)))
                if not chunk:
                    return
                self.output.extend(chunk)
            self.full.set()
        except (OSError, ValueError):
            return
        finally:
            try:
                self._stream.close()
            except (OSError, ValueError):
                pass
