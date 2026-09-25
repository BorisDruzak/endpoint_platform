"""Typed, service-SID-gated Browser Sensor policy helper protocol."""

from __future__ import annotations

import json
import logging
import struct
from hashlib import sha1
from threading import Event
from time import monotonic
from typing import Callable, Collection, Literal, Protocol

from .browser_policy import BrowserFamily, BrowserPolicyConflict
from .local_ipc import LocalIpcRejected, SERVICE_SID as AGENT_SERVICE_SID


PIPE_NAME = r"\\.\pipe\EndpointPlatform.BrowserPolicy.v1"
HELPER_SERVICE_NAME = "EndpointBrowserPolicy"
_REQUEST_SCHEMA = "endpoint_browser_policy_request_v1"
_REPLY_SCHEMA = "endpoint_browser_policy_reply_v1"
_MAX_REQUEST_BYTES = 1024
_LOG = logging.getLogger(__name__)
Operation = Literal["apply", "relinquish"]


def _service_sid(service_name: str) -> str:
    digest = sha1(service_name.upper().encode("utf-16-le")).digest()
    return "S-1-5-80-" + "-".join(str(part) for part in struct.unpack("<IIIII", digest))


HELPER_SERVICE_SID = _service_sid(HELPER_SERVICE_NAME)
_AGENT_PIPE_ACCESS = 0x00100003  # SYNCHRONIZE | read/write data; no pipe creation


class BrowserPolicyRequestError(ValueError):
    """Reject a malformed or non-fixed helper request."""


class PolicyApplicator(Protocol):
    def apply(self, family: BrowserFamily) -> str: ...

    def relinquish(self, family: BrowserFamily) -> str: ...


def create_helper_pipe_security_attributes():
    """Allow SYSTEM to own the pipe and EndpointAgent SID to exchange data."""
    import pywintypes
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;SY)(A;;0x00100003;;;{AGENT_SERVICE_SID})",
        win32security.SDDL_REVISION_1,
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def authorize_agent_pipe_client(pipe_handle: object) -> None:
    """Impersonate the last pipe writer and require EndpointAgent's service SID."""
    import win32api
    import win32con
    import win32pipe
    import win32security

    try:
        win32security.ImpersonateNamedPipeClient(pipe_handle)
        try:
            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(),
                win32con.TOKEN_QUERY,
                True,
            )
            try:
                user, _attributes = win32security.GetTokenInformation(
                    token,
                    win32security.TokenUser,
                )
                session = win32security.GetTokenInformation(
                    token,
                    win32security.TokenSessionId,
                )
                groups = win32security.GetTokenInformation(
                    token,
                    win32security.TokenGroups,
                )
                enabled = {
                    win32security.ConvertSidToStringSid(sid)
                    for sid, attributes in groups
                    if attributes & win32security.SE_GROUP_ENABLED
                }
                accepted = agent_identity_allowed(
                    user_sid=win32security.ConvertSidToStringSid(user),
                    group_sids=enabled,
                    session_id=session,
                )
            finally:
                token.Close()
        finally:
            win32security.RevertToSelf()
        if not accepted or win32pipe.GetNamedPipeClientSessionId(pipe_handle) != 0:
            raise LocalIpcRejected("browser policy pipe client rejected")
    except LocalIpcRejected:
        raise
    except Exception as error:
        raise LocalIpcRejected(
            "browser policy pipe client identity unavailable"
        ) from error


def authorize_helper_pipe_server(pipe_handle: object) -> None:
    """Require the opposite pipe endpoint to be our LocalSystem helper service."""
    import win32api
    import win32con
    import win32pipe
    import win32security

    try:
        process_id = win32pipe.GetNamedPipeServerProcessId(pipe_handle)
        process = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            process_id,
        )
        try:
            token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
            try:
                user, _attributes = win32security.GetTokenInformation(
                    token,
                    win32security.TokenUser,
                )
                session = win32security.GetTokenInformation(
                    token,
                    win32security.TokenSessionId,
                )
                groups = win32security.GetTokenInformation(
                    token,
                    win32security.TokenGroups,
                )
                enabled = {
                    win32security.ConvertSidToStringSid(sid)
                    for sid, attributes in groups
                    if attributes & win32security.SE_GROUP_ENABLED
                }
                accepted = helper_identity_allowed(
                    user_sid=win32security.ConvertSidToStringSid(user),
                    group_sids=enabled,
                    session_id=session,
                )
            finally:
                token.Close()
        finally:
            process.Close()
        if not accepted:
            raise LocalIpcRejected("browser policy pipe server rejected")
    except LocalIpcRejected:
        raise
    except Exception as error:
        raise LocalIpcRejected(
            "browser policy pipe server identity unavailable"
        ) from error


def create_helper_server_pipe():
    """Create one first-instance local pipe under the helper's protected DACL."""
    import win32file
    import win32pipe

    return win32pipe.CreateNamedPipe(
        PIPE_NAME,
        win32pipe.PIPE_ACCESS_DUPLEX
        | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE
        | win32file.FILE_FLAG_OVERLAPPED,
        win32pipe.PIPE_TYPE_BYTE
        | win32pipe.PIPE_READMODE_BYTE
        | win32pipe.PIPE_WAIT
        | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        _MAX_REQUEST_BYTES + 4,
        _MAX_REQUEST_BYTES + 4,
        2000,
        create_helper_pipe_security_attributes(),
    )


def connect_helper_client_pipe():
    """Open only the fixed helper endpoint and verify its OS service token."""
    import win32con
    import win32file

    handle = win32file.CreateFile(
        PIPE_NAME,
        _AGENT_PIPE_ACCESS,
        0,
        None,
        win32con.OPEN_EXISTING,
        win32file.FILE_FLAG_OVERLAPPED,
        None,
    )
    try:
        authorize_helper_pipe_server(handle)
    except BaseException:
        win32file.CloseHandle(handle)
        raise
    return handle


def agent_identity_allowed(
    *,
    user_sid: str,
    group_sids: Collection[str],
    session_id: int,
) -> bool:
    return (
        user_sid == "S-1-5-19"
        and AGENT_SERVICE_SID in group_sids
        and isinstance(session_id, int)
        and not isinstance(session_id, bool)
        and session_id == 0
    )


def helper_identity_allowed(
    *,
    user_sid: str,
    group_sids: Collection[str],
    session_id: int,
) -> bool:
    return (
        user_sid == "S-1-5-18"
        and HELPER_SERVICE_SID in group_sids
        and isinstance(session_id, int)
        and not isinstance(session_id, bool)
        and session_id == 0
    )


def decode_policy_request(payload: bytes) -> tuple[Operation, BrowserFamily]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= _MAX_REQUEST_BYTES:
        raise BrowserPolicyRequestError("invalid browser policy request size")
    try:
        request = json.loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise BrowserPolicyRequestError("invalid browser policy request") from error
    if (
        not isinstance(request, dict)
        or set(request)
        != {
            "schema_version",
            "operation",
            "browser_family",
        }
        or request["schema_version"] != _REQUEST_SCHEMA
    ):
        raise BrowserPolicyRequestError("invalid browser policy request schema")
    operation = request["operation"]
    family = request["browser_family"]
    if operation not in ("apply", "relinquish") or family not in ("chrome", "yandex"):
        raise BrowserPolicyRequestError("invalid browser policy operation")
    return operation, family


def _reply(status: str) -> bytes:
    return json.dumps(
        {"schema_version": _REPLY_SCHEMA, "status": status},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def handle_policy_frame(
    pipe_handle: object,
    payload: bytes,
    applicator: PolicyApplicator,
    *,
    authorize: Callable[[object], None],
) -> bytes:
    """Authenticate the actual pipe writer before parsing each typed request."""
    authorize(pipe_handle)
    try:
        operation, family = decode_policy_request(payload)
    except BrowserPolicyRequestError:
        return _reply("INVALID_REQUEST")
    try:
        status = (
            applicator.apply(family)
            if operation == "apply"
            else applicator.relinquish(family)
        )
    except BrowserPolicyConflict:
        return _reply("POLICY_CONFLICT")
    except Exception:
        _LOG.exception("Browser policy helper failed")
        return _reply("HELPER_ERROR")
    if status not in ("APPLIED", "EXTERNALLY_MANAGED"):
        return _reply("HELPER_ERROR")
    return _reply(status)


def send_policy_request(operation: Operation, family: BrowserFamily) -> str:
    """Ask the authenticated fixed helper to change one browser policy entry."""
    import win32file

    from .sensor_pipe_listener import _read_frame, _write_frame

    request = json.dumps(
        {
            "schema_version": _REQUEST_SCHEMA,
            "operation": operation,
            "browser_family": family,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    decode_policy_request(request)
    handle = connect_helper_client_pipe()
    try:
        stop = Event()
        _write_frame(handle, request, stop, monotonic() + 5)
        reply = _read_frame(handle, stop, monotonic() + 5)
    finally:
        win32file.CloseHandle(handle)
    if len(reply) > _MAX_REQUEST_BYTES:
        raise BrowserPolicyRequestError("invalid browser policy reply size")
    try:
        parsed = json.loads(reply.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise BrowserPolicyRequestError("invalid browser policy reply") from error
    if not isinstance(parsed, dict) or set(parsed) != {"schema_version", "status"}:
        raise BrowserPolicyRequestError("invalid browser policy reply schema")
    if parsed["schema_version"] != _REPLY_SCHEMA or parsed["status"] not in {
        "APPLIED",
        "EXTERNALLY_MANAGED",
        "POLICY_CONFLICT",
        "INVALID_REQUEST",
        "HELPER_ERROR",
    }:
        raise BrowserPolicyRequestError("invalid browser policy reply status")
    return parsed["status"]
