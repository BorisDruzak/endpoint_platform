"""Kernel-only USB hotplug metadata, never user data or raw sysfs paths.

Linux 6.12 lib/kobject_uevent.c marks kernel multicast group 1 with port/UID/GID
zero. Validate both address and SCM_CREDENTIALS before parsing a bounded frame.
"""
from __future__ import annotations

import errno

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import logging
import re
import socket
import struct
from threading import Event, Thread
from uuid import UUID, NAMESPACE_URL, uuid5

from endpoint_contracts.security_events import UsbEventMetadataV1
from pc_agent.security.usb_projection import project_usb_event

MAX_MESSAGE_BYTES = 16384
_UCRED = struct.Struct('iII')
_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class UsbChange:
    action: str
    event_identifier: UUID
    metadata: UsbEventMetadataV1


def decode_usb_event(data: bytes, *, boot_id: UUID, sender: tuple[int, int],
                     credentials: tuple[int, int, int] | None, flags: int = 0) -> UsbChange | None:
    if sender != (0, 1) or credentials != (0, 0, 0):
        raise PermissionError('USB_KERNEL_SENDER_REQUIRED')
    if flags & (getattr(socket, 'MSG_TRUNC', 0x20) | getattr(socket, 'MSG_CTRUNC', 8)):
        raise ValueError('USB_FRAME_TRUNCATED')
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_MESSAGE_BYTES or not data.endswith(b'\0'):
        raise ValueError('USB_FRAME_INVALID')
    fields = data.split(b'\0')
    if len(fields) > 130:
        raise ValueError('USB_FIELD_LIMIT')
    wanted = {b'ACTION', b'DEVPATH', b'SUBSYSTEM', b'DEVTYPE', b'PRODUCT', b'TYPE', b'SEQNUM', b'SYNTH_UUID'}
    values = {}
    for field in fields[1:-1]:
        key, separator, raw = field.partition(b'=')
        if key in wanted:
            if not separator or key in values or len(raw) > 2048:
                raise ValueError('USB_FIELD_INVALID')
            values[key] = raw.decode('ascii')
    if (values.get(b'SUBSYSTEM') != 'usb' or values.get(b'DEVTYPE') != 'usb_device'
        or values.get(b'ACTION') not in {'add', 'remove'} or b'SYNTH_UUID' in values):
        return None
    action, path = values[b'ACTION'], values.get(b'DEVPATH', '')
    if (not path.startswith('/devices/') or len(path) > 1024
        or re.fullmatch(r'/devices/[A-Za-z0-9_./:@!+\-]+', path) is None
        or any(part in {'.', '..', ''} for part in path[1:].split('/'))
        or fields[0] != f'{action}@{path}'.encode('ascii')):
        raise ValueError('USB_HEADER_INVALID')
    product = values.get(b'PRODUCT', '')
    match = re.fullmatch(r'([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/[0-9a-fA-F]{1,4}', product)
    sequence = values.get(b'SEQNUM', '')
    if match is None or not re.fullmatch(r'[1-9][0-9]{0,19}', sequence) or int(sequence) >= 2**64:
        raise ValueError('USB_ID_INVALID')
    kinds = re.fullmatch(r'([0-9]{1,3})/[0-9]{1,3}/[0-9]{1,3}', values.get(b'TYPE', ''))
    device_class = {3: 'hid', 7: 'printer', 8: 'mass_storage'}.get(int(kinds[1])) if kinds else None
    vendor, product_id = (int(value, 16) for value in match.groups())
    metadata = UsbEventMetadataV1(vendor=f'VID_{vendor:04X}', product=f'PID_{product_id:04X}',
                                  device_class=device_class, removable=True)
    return UsbChange(action, uuid5(NAMESPACE_URL, f'endpoint:linux:usb:{boot_id}:{sequence}'), metadata)


def project_usb_change(change: UsbChange, policy, *, occurred_at: datetime):
    return project_usb_event(change.action, change.metadata, policy, occurred_at=occurred_at,
                             event_identifier=change.event_identifier)


class UsbNotifications:
    """One unprivileged kernel subscription; failure is isolated from Core."""

    def __init__(self, on_change):
        self._on_change = on_change
        self._socket = None
        self._thread = None
        self._stop = Event()
        self._healthy = False
        self.failed = 0
        self.rejected = 0

    @property
    def available(self):
        return bool(self._healthy and self._thread is not None and self._thread.is_alive() and not self._stop.is_set())

    def start(self):
        if self._thread is not None:
            raise RuntimeError('USB source already started')
        self._boot_id = UUID(Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip())
        connection = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 15)
        try:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
            connection.bind((0, 1))
            connection.settimeout(0.25)
        except BaseException:
            connection.close()
            raise
        self._socket = connection
        self._stop.clear()
        self._healthy = True
        self._thread = Thread(target=self._run, name='EndpointLinuxUsb', daemon=True)
        try:
            self._thread.start()
        except BaseException:
            connection.close()
            self._socket = None
            self._thread = None
            self._healthy = False
            raise

    def _run(self):
        try:
            while not self._stop.is_set():
                try:
                    data, ancillary, flags, sender = self._socket.recvmsg(MAX_MESSAGE_BYTES, socket.CMSG_SPACE(_UCRED.size))
                except socket.timeout:
                    continue
                except OSError as exc:
                    if exc.errno != errno.ENOBUFS:
                        raise
                    self.failed += 1
                    self._healthy = False
                    _LOG.warning('Linux USB kernel receive buffer overflow')
                    continue
                credentials = [_UCRED.unpack(raw) for level, kind, raw in ancillary
                    if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == _UCRED.size]
                try:
                    change = decode_usb_event(data, boot_id=self._boot_id, sender=sender,
                        credentials=credentials[0] if len(credentials) == 1 else None, flags=flags)
                except PermissionError:
                    self.rejected += 1
                    continue
                if change is not None:
                    # One frozen pending record bounds user-space memory. The
                    # kernel receive buffer remains bounded while persistence
                    # is unavailable; ENOBUFS above exposes any overflow.
                    while not self._stop.is_set():
                        try:
                            self._on_change(change)
                        except Exception:
                            if self._healthy:
                                _LOG.warning('Linux USB persistence is unavailable')
                            self._healthy = False
                            self.failed += 1
                            if self._stop.wait(1):
                                break
                        else:
                            self._healthy = True
                            break
        except Exception:
            if not self._stop.is_set():
                self.failed += 1
                _LOG.warning('Linux USB source is unavailable')
        finally:
            self._healthy = False

    def stop(self):
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                raise TimeoutError('USB source did not stop')
            self._thread = None
        self._socket = None
