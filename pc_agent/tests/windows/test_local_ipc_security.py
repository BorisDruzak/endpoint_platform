"""The local sensor pipe authorizes an OS-backed interactive SID/session."""

import os
import threading
from uuid import uuid4

import pytest

from pc_agent.platform.windows.local_ipc import (
    CLIENT_ACCESS_MASK,
    ClientIdentity,
    LocalIpcRejected,
    PIPE_NAME,
    SERVICE_ACCOUNT_NAME,
    SERVICE_SID,
    authorize_pipe_client,
    authorize_pipe_server,
    client_identity_allowed,
    create_pipe_security_attributes,
    create_server_pipe,
    read_pipe_frame,
    write_pipe_frame,
)


ACTIVE = ClientIdentity(
    user_sid="S-1-5-21-123-456-789-1001",
    logon_sid="S-1-5-5-10-20",
    token_session_id=3,
    group_sids=frozenset({"S-1-5-4", "S-1-5-11", "S-1-5-5-10-20"}),
)


def test_pipe_has_fixed_local_name_and_client_cannot_create_server_instance() -> None:
    assert PIPE_NAME == r"\\.\pipe\EndpointPlatform.Agent.Sensor.v1"
    assert CLIENT_ACCESS_MASK & 0x4 == 0  # FILE_CREATE_PIPE_INSTANCE
    assert CLIENT_ACCESS_MASK & 0x100000  # SYNCHRONIZE


@pytest.mark.parametrize("identity,pipe_session,active", [
    (ACTIVE, 4, {3}),
    (ACTIVE, 3, {4}),
    (ClientIdentity(ACTIVE.user_sid, ACTIVE.logon_sid, 0, ACTIVE.group_sids), 0, {0}),
    (ClientIdentity(ACTIVE.user_sid, ACTIVE.logon_sid, 3, frozenset()), 3, {3}),
    (ClientIdentity(ACTIVE.user_sid, ACTIVE.logon_sid, 3, frozenset({"S-1-5-4"})), 3, {3}),
    (ClientIdentity("S-1-5-19", ACTIVE.logon_sid, 3, ACTIVE.group_sids), 3, {3}),
    (ClientIdentity(ACTIVE.user_sid, "S-1-5-19", 3, ACTIVE.group_sids), 3, {3}),
])
def test_session_or_sid_mismatch_is_rejected(identity, pipe_session, active) -> None:
    assert not client_identity_allowed(identity, pipe_session_id=pipe_session, active_session_ids=active)


def test_active_interactive_identity_is_accepted() -> None:
    assert client_identity_allowed(ACTIVE, pipe_session_id=3, active_session_ids={3})


@pytest.mark.skipif(os.name != "nt", reason="Windows security descriptor")
def test_real_pipe_dacl_grants_interactive_data_only() -> None:
    import win32security

    security = create_pipe_security_attributes()
    dacl = security.SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
    rights = {
        win32security.ConvertSidToStringSid(dacl.GetAce(index)[2]): dacl.GetAce(index)[1]
        for index in range(dacl.GetAceCount())
    }
    assert rights["S-1-5-4"] == CLIENT_ACCESS_MASK
    assert rights["S-1-5-4"] & 0x4 == 0
    assert rights[SERVICE_SID] == 0x10000000  # The EndpointAgent service owns server instances.
    assert "S-1-5-19" not in rights  # Other LocalService processes cannot own this pipe.
    assert "S-1-1-0" not in rights  # Everyone


@pytest.mark.skipif(os.name != "nt", reason="Windows service SID mapping")
def test_fixed_service_sid_matches_windows_account_mapping_when_installed() -> None:
    import pywintypes
    import win32security

    try:
        sid, _domain, _kind = win32security.LookupAccountName(None, SERVICE_ACCOUNT_NAME)
    except pywintypes.error:
        pytest.skip("EndpointAgent service is not installed")
    assert SERVICE_SID == win32security.ConvertSidToStringSid(sid)


@pytest.mark.integration
@pytest.mark.skipif(os.name != "nt", reason="Windows named pipe")
def test_named_pipe_roundtrip_uses_os_client_identity() -> None:
    import pywintypes
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32security
    import win32ts

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        session_id = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        user_sid = win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0],
        )
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
    finally:
        token.Close()
    enabled_groups = {
        win32security.ConvertSidToStringSid(sid)
        for sid, attributes in groups if attributes & win32security.SE_GROUP_ENABLED
    }
    active_sessions = {
        row["SessionId"] for row in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE)
        if row["State"] == win32ts.WTSActive
    }
    if (
        session_id not in active_sessions or "S-1-5-4" not in enabled_groups
        or (user_sid != "S-1-5-18" and "S-1-5-32-544" not in enabled_groups)
    ):
        pytest.skip("requires an active interactive administrator session")

    pipe_name = f"{PIPE_NAME}.test.{uuid4().hex}"
    server = create_server_pipe(pipe_name=pipe_name)
    received: list[bytes] = []
    failed: list[BaseException] = []

    def client_run() -> None:
        try:
            client = win32file.CreateFile(
                pipe_name, CLIENT_ACCESS_MASK, 0, None, win32con.OPEN_EXISTING, 0, None,
            )
            try:
                with pytest.raises(LocalIpcRejected):
                    authorize_pipe_server(client)  # This test server is an admin process.
                write_pipe_frame(client, b"request")
                received.append(read_pipe_frame(client))
            finally:
                win32file.CloseHandle(client)
        except BaseException as error:
            failed.append(error)

    client_thread = threading.Thread(target=client_run, daemon=True)
    client_thread.start()
    try:
        try:
            win32pipe.ConnectNamedPipe(server, None)
        except pywintypes.error as error:
            if error.winerror != 535:  # ERROR_PIPE_CONNECTED
                raise
        assert read_pipe_frame(server) == b"request"
        identity = authorize_pipe_client(server)
        assert identity.token_session_id > 0
        write_pipe_frame(server, b"ack")
        client_thread.join(timeout=5)
    finally:
        win32pipe.DisconnectNamedPipe(server)
        win32file.CloseHandle(server)
    assert not client_thread.is_alive()
    assert not failed
    assert received == [b"ack"]
