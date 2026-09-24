"""Windows named-pipe identity checks for the per-user sensor boundary.

Only the LocalService Agent creates the pipe. An interactive client may open
it for data transfer, but cannot create a competing server instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
import re
import struct
from typing import Collection


PIPE_NAME = r"\\.\pipe\EndpointPlatform.Agent.Sensor.v1"
CLIENT_ACCESS_MASK = 0x00100003  # SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA
MAX_IPC_MESSAGE_BYTES = 16 * 1024
SERVICE_ACCOUNT_NAME = r"NT SERVICE\EndpointAgent"


def _fixed_service_sid() -> str:
    # Windows derives per-service SIDs from the uppercase UTF-16LE service name.
    digest = sha1("ENDPOINTAGENT".encode("utf-16-le")).digest()
    return "S-1-5-80-" + "-".join(str(part) for part in struct.unpack("<IIIII", digest))


SERVICE_SID = _fixed_service_sid()

_SID_PATTERN = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
_LOGON_SID_PATTERN = re.compile(r"S-1-5-5-[0-9]+-[0-9]+\Z", re.ASCII)
_SERVICE_USER_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7"})
_INTERACTIVE_SID = "S-1-5-4"


class LocalIpcRejected(PermissionError):
    """A local IPC peer failed OS-backed authorization."""


@dataclass(frozen=True)
class ClientIdentity:
    user_sid: str
    logon_sid: str
    token_session_id: int
    group_sids: frozenset[str]


def client_identity_allowed(
    identity: ClientIdentity,
    *,
    pipe_session_id: int,
    active_session_ids: Collection[int],
) -> bool:
    """Authorize only an active, interactive user in the pipe client's session."""
    if not isinstance(identity.token_session_id, int) or isinstance(identity.token_session_id, bool):
        return False
    if identity.token_session_id <= 0 or identity.token_session_id != pipe_session_id:
        return False
    if pipe_session_id not in active_session_ids:
        return False
    if not _SID_PATTERN.fullmatch(identity.user_sid) or identity.user_sid in _SERVICE_USER_SIDS:
        return False
    if not _LOGON_SID_PATTERN.fullmatch(identity.logon_sid):
        return False
    if _INTERACTIVE_SID not in identity.group_sids:
        return False
    if identity.logon_sid not in identity.group_sids:
        return False
    return True


def create_pipe_security_attributes():
    """Build a protected DACL with data-only access for interactive clients."""
    import pywintypes
    import win32security

    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{SERVICE_SID})"
        "(A;;0x00100003;;;IU)",
        win32security.SDDL_REVISION_1,
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def create_server_pipe(*, pipe_name: str = PIPE_NAME):
    """Create the single local server instance; fail if another owns the name."""
    import win32pipe

    if not pipe_name.startswith(r"\\.\pipe\EndpointPlatform.Agent."):
        raise ValueError("invalid Endpoint Agent pipe name")
    return win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX | win32pipe.FILE_FLAG_FIRST_PIPE_INSTANCE,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE |
        win32pipe.PIPE_WAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        MAX_IPC_MESSAGE_BYTES + 4,
        MAX_IPC_MESSAGE_BYTES + 4,
        2000,
        create_pipe_security_attributes(),
    )


def connect_client_pipe(*, pipe_name: str = PIPE_NAME):
    """Open a server-owned pipe for bounded request/ACK exchange."""
    import win32con
    import win32file

    if not pipe_name.startswith(r"\\.\pipe\EndpointPlatform.Agent."):
        raise ValueError("invalid Endpoint Agent pipe name")
    handle = win32file.CreateFile(
        pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
    )
    try:
        authorize_pipe_server(handle)
    except BaseException:
        win32file.CloseHandle(handle)
        raise
    return handle


def _read_exact(pipe_handle, count: int) -> bytes:
    import win32file

    data = bytearray()
    while len(data) < count:
        result, part = win32file.ReadFile(pipe_handle, count - len(data))
        if result != 0 or not part:
            raise LocalIpcRejected("incomplete local IPC frame")
        data.extend(part)
    return bytes(data)


def read_pipe_frame(pipe_handle) -> bytes:
    """Read at most one bounded frame; never allocate from an unchecked size."""
    size = struct.unpack("<I", _read_exact(pipe_handle, 4))[0]
    if not 1 <= size <= MAX_IPC_MESSAGE_BYTES:
        raise LocalIpcRejected("invalid local IPC frame size")
    return _read_exact(pipe_handle, size)


def write_pipe_frame(pipe_handle, payload: bytes) -> None:
    import win32file

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_IPC_MESSAGE_BYTES:
        raise ValueError("invalid local IPC payload size")
    result, written = win32file.WriteFile(pipe_handle, struct.pack("<I", len(payload)) + payload)
    if result != 0 or written != len(payload) + 4:
        raise LocalIpcRejected("incomplete local IPC write")


def _impersonated_client_identity(pipe_handle) -> ClientIdentity:
    """Read the *last message writer's* token and always revert impersonation."""
    import win32api
    import win32con
    import win32security

    win32security.ImpersonateNamedPipeClient(pipe_handle)
    try:
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True,
        )
        try:
            user, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
            session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
            groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
            logon_groups = [
                win32security.ConvertSidToStringSid(sid)
                for sid, attributes in groups
                if attributes & win32security.SE_GROUP_LOGON_ID == win32security.SE_GROUP_LOGON_ID
            ]
            if len(logon_groups) != 1:
                raise LocalIpcRejected("ambiguous local IPC logon identity")
            return ClientIdentity(
                user_sid=win32security.ConvertSidToStringSid(user),
                logon_sid=logon_groups[0],
                token_session_id=session,
                group_sids=frozenset(
                    win32security.ConvertSidToStringSid(sid)
                    for sid, attributes in groups
                    if attributes & win32security.SE_GROUP_ENABLED
                ),
            )
        finally:
            token.Close()
    finally:
        win32security.RevertToSelf()


def authorize_pipe_client(pipe_handle) -> ClientIdentity:
    """Validate the writer's token, pipe session and current WTS session state."""
    import win32pipe
    import win32ts

    try:
        identity = _impersonated_client_identity(pipe_handle)
        pipe_session_id = win32pipe.GetNamedPipeClientSessionId(pipe_handle)
        active_sessions = {
            row["SessionId"]
            for row in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE)
            if row["State"] == win32ts.WTSActive
        }
        if client_identity_allowed(
            identity, pipe_session_id=pipe_session_id, active_session_ids=active_sessions,
        ):
            return identity
    except Exception as error:
        raise LocalIpcRejected("local IPC client identity unavailable") from error
    raise LocalIpcRejected("local IPC client identity rejected")


def authorize_pipe_server(pipe_handle) -> None:
    """Reject a first-instance squat unless it is the EndpointAgent service."""
    import win32api
    import win32con
    import win32pipe
    import win32security

    try:
        process_id = win32pipe.GetNamedPipeServerProcessId(pipe_handle)
        process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
        try:
            token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
            try:
                user, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
                groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
                enabled_groups = {
                    win32security.ConvertSidToStringSid(sid)
                    for sid, attributes in groups
                    if attributes & win32security.SE_GROUP_ENABLED
                }
                if (
                    win32security.ConvertSidToStringSid(user) == "S-1-5-19"
                    and SERVICE_SID in enabled_groups
                ):
                    return
            finally:
                token.Close()
        finally:
            process.Close()
    except Exception as error:
        raise LocalIpcRejected("local IPC server identity unavailable") from error
    raise LocalIpcRejected("local IPC server identity rejected")


def resolve_user_login(identity: ClientIdentity) -> str | None:
    """Resolve login from the OS token SID, never from client-supplied JSON."""
    import win32security

    try:
        sid = win32security.ConvertStringSidToSid(identity.user_sid)
        name, domain, _kind = win32security.LookupAccountSid(None, sid)
        login = f"{domain}\\{name}" if domain else name
        if not 1 <= len(login) <= 256 or any(ord(char) < 32 for char in login):
            return None
        return login
    except Exception:
        return None
