"""Only the fixed EndpointAgent service may request browser-policy changes."""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows.browser_policy import BrowserPolicyConflict
from pc_agent.platform.windows.browser_policy_helper import (
    AGENT_SERVICE_SID,
    HELPER_SERVICE_SID,
    PIPE_NAME,
    BrowserPolicyRequestError,
    agent_identity_allowed,
    authorize_agent_pipe_client,
    authorize_helper_pipe_server,
    connect_helper_client_pipe,
    create_helper_pipe_security_attributes,
    create_helper_server_pipe,
    decode_policy_request,
    handle_policy_frame,
    helper_identity_allowed,
    publish_helper_identity_acl,
    send_policy_request,
)
from pc_agent.platform.windows.local_ipc import LocalIpcRejected
from pc_agent.platform.windows.sensor_pipe_listener import LocalSensorPipeListener


def _frame(**overrides: object) -> bytes:
    payload = {
        "schema_version": "endpoint_browser_policy_request_v1",
        "operation": "apply",
        "browser_family": "chrome",
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def test_request_accepts_only_versioned_apply_or_relinquish_for_fixed_browsers() -> (
    None
):
    assert decode_policy_request(_frame()) == ("apply", "chrome")
    assert decode_policy_request(
        _frame(operation="relinquish", browser_family="yandex")
    ) == (
        "relinquish",
        "yandex",
    )
    for invalid in (
        _frame(operation="set_registry"),
        _frame(browser_family="edge"),
        _frame(extension_id="abcdefghijklmnopabcdefghijklmnop"),
        _frame(registry_path=r"SOFTWARE\Other"),
        _frame(update_url="https://example.org/update.xml"),
        _frame(schema_version="endpoint_browser_policy_request_v2"),
        b"{invalid",
        b" " * 1025,
    ):
        with pytest.raises(BrowserPolicyRequestError):
            decode_policy_request(invalid)


def test_agent_identity_requires_localservice_and_enabled_service_sid() -> None:
    assert agent_identity_allowed(
        user_sid="S-1-5-19",
        group_sids={AGENT_SERVICE_SID},
        session_id=0,
    )
    assert not agent_identity_allowed(
        user_sid="S-1-5-19",
        group_sids=set(),
        session_id=0,
    )
    assert not agent_identity_allowed(
        user_sid="S-1-5-18",
        group_sids={AGENT_SERVICE_SID},
        session_id=0,
    )
    assert not agent_identity_allowed(
        user_sid="S-1-5-19",
        group_sids={AGENT_SERVICE_SID},
        session_id=2,
    )


def test_agent_accepts_only_system_helper_service_as_pipe_server() -> None:
    assert helper_identity_allowed(
        user_sid="S-1-5-18",
        group_sids={HELPER_SERVICE_SID},
        session_id=0,
    )
    assert not helper_identity_allowed(
        user_sid="S-1-5-18",
        group_sids=set(),
        session_id=0,
    )
    assert not helper_identity_allowed(
        user_sid="S-1-5-19",
        group_sids={HELPER_SERVICE_SID},
        session_id=0,
    )


def test_handler_authorizes_every_request_before_applying() -> None:
    calls: list[str] = []

    class Applicator:
        def apply(self, family: str) -> str:
            calls.append(family)
            return "APPLIED"

    def deny(_handle: object) -> None:
        raise PermissionError("wrong service SID")

    with pytest.raises(PermissionError):
        handle_policy_frame(object(), _frame(), Applicator(), authorize=deny)
    assert calls == []

    def allow(_handle: object) -> None:
        calls.append("authorized")

    reply = json.loads(
        handle_policy_frame(object(), _frame(), Applicator(), authorize=allow)
    )
    assert calls == ["authorized", "chrome"]
    assert reply == {
        "schema_version": "endpoint_browser_policy_reply_v1",
        "status": "APPLIED",
    }


def test_handler_reports_conflict_without_exposing_registry_content() -> None:
    class Applicator:
        def apply(self, _family: str) -> str:
            raise BrowserPolicyConflict("POLICY_CONFLICT")

    reply = json.loads(
        handle_policy_frame(object(), _frame(), Applicator(), authorize=lambda _: None)
    )
    assert reply == {
        "schema_version": "endpoint_browser_policy_reply_v1",
        "status": "POLICY_CONFLICT",
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows pipe security descriptor")
def test_helper_pipe_dacl_grants_data_access_only_to_agent_service_sid() -> None:
    import win32security

    assert PIPE_NAME == r"\\.\pipe\EndpointPlatform.BrowserPolicy.v1"
    descriptor = create_helper_pipe_security_attributes().SECURITY_DESCRIPTOR
    dacl = descriptor.GetSecurityDescriptorDacl()
    rights = {
        win32security.ConvertSidToStringSid(dacl.GetAce(index)[2]): dacl.GetAce(index)[
            1
        ]
        for index in range(dacl.GetAceCount())
    }
    assert rights[AGENT_SERVICE_SID] == 0x00100083
    assert rights[AGENT_SERVICE_SID] & 0x4 == 0
    assert rights[AGENT_SERVICE_SID] & 0x80
    assert rights["S-1-5-18"] == 0x10000000
    assert "S-1-5-4" not in rights
    assert "S-1-1-0" not in rights


def test_helper_grants_agent_only_identity_query_rights(monkeypatch) -> None:
    events: list[tuple[object, ...]] = []

    class Dacl:
        def GetAceCount(self) -> int:
            return 0

        def AddAccessAllowedAceEx(self, *args) -> None:
            events.append(("grant", *args))

    class Descriptor:
        def GetSecurityDescriptorDacl(self) -> Dacl:
            return Dacl()

    class Handle:
        def Close(self) -> None:
            events.append(("close",))

    security = SimpleNamespace(
        SE_KERNEL_OBJECT=6,
        DACL_SECURITY_INFORMATION=4,
        ACL_REVISION=2,
        GetSecurityInfo=lambda handle, *_: events.append(("read", handle)) or Descriptor(),
        SetSecurityInfo=lambda handle, _, __, ___, ____, acl, _____: events.append(
            ("set", handle, acl)
        ),
        ConvertStringSidToSid=lambda sid: sid,
        OpenProcessToken=lambda process, rights: events.append(
            ("open-token", process, rights)
        ) or Handle(),
    )
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetCurrentProcess=lambda: "process"))
    monkeypatch.setitem(
        sys.modules,
        "win32con",
        SimpleNamespace(
            PROCESS_QUERY_LIMITED_INFORMATION=0x1000,
            TOKEN_QUERY=0x8,
            READ_CONTROL=0x20000,
            WRITE_DAC=0x40000,
        ),
    )

    publish_helper_identity_acl()

    grants = [item for item in events if item[0] == "grant"]
    assert grants == [
        ("grant", 2, 0, 0x1000, AGENT_SERVICE_SID),
        ("grant", 2, 0, 0x8, AGENT_SERVICE_SID),
    ]
    assert ("open-token", "process", 0x60008) in events
    assert ("close",) in events


@pytest.mark.parametrize(
    "groups,accepted",
    [
        ([(AGENT_SERVICE_SID, 4)], True),
        ([], False),
    ],
)
def test_os_pipe_client_authentication_reverts_impersonation(
    monkeypatch,
    groups,
    accepted,
) -> None:
    actions: list[str] = []

    class Token:
        def Close(self) -> None:
            actions.append("close-token")

    security = SimpleNamespace(
        TokenUser=1,
        TokenSessionId=2,
        TokenGroups=3,
        SE_GROUP_ENABLED=4,
        ImpersonateNamedPipeClient=lambda _: actions.append("impersonate"),
        OpenThreadToken=lambda *_: Token(),
        GetTokenInformation=lambda _token, kind: {
            1: ("S-1-5-19", 0),
            2: 0,
            3: groups,
        }[kind],
        ConvertSidToStringSid=lambda sid: sid,
        RevertToSelf=lambda: actions.append("revert"),
    )
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(
        sys.modules,
        "win32api",
        SimpleNamespace(GetCurrentThread=lambda: object()),
    )
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(TOKEN_QUERY=1))
    monkeypatch.setitem(
        sys.modules,
        "win32pipe",
        SimpleNamespace(GetNamedPipeClientSessionId=lambda _: 0),
    )
    if accepted:
        authorize_agent_pipe_client(object())
    else:
        with pytest.raises(LocalIpcRejected):
            authorize_agent_pipe_client(object())
    assert actions == ["impersonate", "close-token", "revert"]


@pytest.mark.parametrize(
    "groups,accepted",
    [
        ([(HELPER_SERVICE_SID, 4)], True),
        ([], False),
    ],
)
def test_agent_checks_actual_pipe_server_process_identity(
    monkeypatch,
    groups,
    accepted,
) -> None:
    closed: list[str] = []

    class Process:
        def Close(self) -> None:
            closed.append("process")

    class Token:
        def Close(self) -> None:
            closed.append("token")

    security = SimpleNamespace(
        TokenUser=1,
        TokenSessionId=2,
        TokenGroups=3,
        SE_GROUP_ENABLED=4,
        OpenProcessToken=lambda *_: Token(),
        GetTokenInformation=lambda _token, kind: {
            1: ("S-1-5-18", 0),
            2: 0,
            3: groups,
        }[kind],
        ConvertSidToStringSid=lambda sid: sid,
    )
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(
        sys.modules,
        "win32api",
        SimpleNamespace(OpenProcess=lambda *_: Process()),
    )
    monkeypatch.setitem(
        sys.modules,
        "win32con",
        SimpleNamespace(
            PROCESS_QUERY_LIMITED_INFORMATION=1,
            TOKEN_QUERY=2,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "win32pipe",
        SimpleNamespace(GetNamedPipeServerProcessId=lambda _: 42),
    )
    if accepted:
        authorize_helper_pipe_server(object())
    else:
        with pytest.raises(LocalIpcRejected):
            authorize_helper_pipe_server(object())
    assert closed == ["token", "process"]


def test_helper_pipe_is_single_instance_local_and_fixed_name(monkeypatch) -> None:
    calls: list[tuple] = []
    fake_pipe = SimpleNamespace(
        PIPE_ACCESS_DUPLEX=1,
        FILE_FLAG_FIRST_PIPE_INSTANCE=2,
        PIPE_TYPE_BYTE=4,
        PIPE_READMODE_BYTE=8,
        PIPE_WAIT=16,
        PIPE_REJECT_REMOTE_CLIENTS=32,
        CreateNamedPipe=lambda *args: calls.append(args) or object(),
    )
    monkeypatch.setitem(sys.modules, "win32pipe", fake_pipe)
    monkeypatch.setitem(
        sys.modules,
        "win32file",
        SimpleNamespace(FILE_FLAG_OVERLAPPED=64),
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_helper.create_helper_pipe_security_attributes",
        lambda: object(),
    )
    create_helper_server_pipe()
    assert calls[0][0] == PIPE_NAME
    assert calls[0][1] == 1 | 2 | 64
    assert calls[0][2] & 32
    assert calls[0][3] == 1


def test_agent_closes_helper_pipe_if_server_identity_fails(monkeypatch) -> None:
    handle = object()
    closed: list[object] = []
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(OPEN_EXISTING=3))
    monkeypatch.setitem(
        sys.modules,
        "win32file",
        SimpleNamespace(
            FILE_FLAG_OVERLAPPED=64,
            CreateFile=lambda *args: handle,
            CloseHandle=lambda value: closed.append(value),
        ),
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_helper.authorize_helper_pipe_server",
        lambda _: (_ for _ in ()).throw(LocalIpcRejected("spoof")),
    )
    with pytest.raises(LocalIpcRejected):
        connect_helper_client_pipe()
    assert closed == [handle]


def test_agent_sends_only_typed_request_and_rejects_malformed_reply(
    monkeypatch,
) -> None:
    handle = object()
    sent: list[bytes] = []
    closed: list[object] = []
    response = {
        "payload": b'{"schema_version":"endpoint_browser_policy_reply_v1","status":"APPLIED"}'
    }
    monkeypatch.setattr(
        "pc_agent.platform.windows.browser_policy_helper.connect_helper_client_pipe",
        lambda: handle,
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.sensor_pipe_listener._write_frame",
        lambda _handle, payload, *_: sent.append(payload),
    )
    monkeypatch.setattr(
        "pc_agent.platform.windows.sensor_pipe_listener._read_frame",
        lambda *_: response["payload"],
    )
    monkeypatch.setitem(
        sys.modules,
        "win32file",
        SimpleNamespace(CloseHandle=lambda value: closed.append(value)),
    )
    assert send_policy_request("apply", "chrome") == "APPLIED"
    assert json.loads(sent[0]) == {
        "schema_version": "endpoint_browser_policy_request_v1",
        "operation": "apply",
        "browser_family": "chrome",
    }
    response["payload"] = (
        b'{"schema_version":"endpoint_browser_policy_reply_v1","status":"APPLIED","registry_path":"bad"}'
    )
    with pytest.raises(BrowserPolicyRequestError):
        send_policy_request("apply", "chrome")
    assert closed == [handle, handle]


def test_helper_can_reuse_bounded_listener_with_its_own_pipe_factory(
    monkeypatch,
) -> None:
    handle = object()
    threads: list[object] = []

    class DormantThread:
        def __init__(self, *, target, args, **_kwargs):
            assert args == (handle,)
            threads.append(target)

        def start(self):
            return None

        def join(self, **_kwargs):
            return None

        def is_alive(self):
            return False

    monkeypatch.setattr(
        "pc_agent.platform.windows.sensor_pipe_listener.Thread",
        DormantThread,
    )
    listener = LocalSensorPipeListener(
        lambda _handle, _payload: b"ok",
        server_factory=lambda: handle,
    )
    listener.start()
    assert len(threads) == 1
    listener.stop()
