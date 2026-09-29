"""The tray receives only a bounded ephemeral proof, never device credentials."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest


def payload():
    return {"challenge_id":str(uuid4()), "code":"123456", "display_code":"123-456",
        "expires_at":(datetime.now(UTC)+timedelta(seconds=600)).isoformat(), "expires_in_seconds":600}


def test_fragment_deep_link_and_strict_challenge_parsing():
    from pc_agent.platform.windows.device_binding import parse_challenge, helpdesk_link, BindingUnavailable
    challenge = parse_challenge(payload())
    assert helpdesk_link(challenge) == "https://helpdesk.sosnadmin.local/app/requester/devices/link#code=123456"
    assert challenge.code not in repr(challenge)
    for bad in ({**payload(),"device_token":"secret"}, {**payload(),"display_code":"999-999"},
                {**payload(),"expires_at":datetime.now(UTC).isoformat()}):
        with pytest.raises(BindingUnavailable):
            parse_challenge(bad)


def test_staging_deep_link_uses_only_an_explicit_approved_https_origin():
    from pc_agent.platform.windows.device_binding import parse_challenge, helpdesk_link, BindingUnavailable
    challenge = parse_challenge(payload())
    assert helpdesk_link(challenge, origin="https://helpdesk-staging.sosnadmin.local").startswith(
        "https://helpdesk-staging.sosnadmin.local/app/requester/devices/link#code=")
    for origin in ("http://helpdesk-staging.sosnadmin.local", "https://example.com",
        "https://helpdesk-staging.sosnadmin.local/other", "https://user@helpdesk-staging.sosnadmin.local"):
        with pytest.raises(BindingUnavailable):
            helpdesk_link(challenge, origin=origin)


@pytest.mark.asyncio
async def test_authenticated_client_uses_existing_session_and_never_follows_redirects():
    import json
    from pc_agent.update_adapter import EndpointUpdateAdapter
    from pc_agent.platform.windows.device_binding import BindingUnavailable

    class Content:
        async def iter_chunked(self, size):
            yield json.dumps(payload()).encode()

    class Response:
        status = 200
        content = Content()
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    class Session:
        response = Response()
        calls = []
        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return self.response

    session = Session()
    adapter = EndpointUpdateAdapter(api_url="https://endpoint.sosnadmin.local", bearer_token=lambda:"fixture-device-token", session=session)
    challenge = await adapter.create_device_binding_challenge()
    assert challenge.code == "123456"
    assert session.calls[-1][0].endswith("/api/v1/device-binding/challenges")
    assert session.calls[-1][1]["json"] == {"purpose":"helpdesk_device_binding"}
    assert session.calls[-1][1]["allow_redirects"] is False
    for status in (302,401,429,500):
        session.response.status = status
        with pytest.raises(BindingUnavailable) as error:
            await adapter.create_device_binding_challenge()
        assert "fixture-device-token" not in str(error.value)


def test_ipc_authorizes_peer_before_challenge_and_bounds_bad_requests():
    from pc_agent.platform.windows.device_binding import BindingPipeHandler
    from pc_agent.platform.windows.local_ipc import LocalIpcRejected
    invoked = []
    handler = BindingPipeHandler(lambda: invoked.append("issued") or payload(),
        authorize=lambda _: (_ for _ in ()).throw(LocalIpcRejected("denied")))
    with pytest.raises(LocalIpcRejected):
        handler.handle(object(), b'{"action":"create"}')
    assert invoked == []
    handler = BindingPipeHandler(lambda: invoked.append("issued") or payload(), authorize=lambda _:None)
    assert b'123456' in handler.handle(object(), b'{"action":"create"}')
    assert invoked == ["issued"]
    for frame in (b'{"action":"create","device_id":"other"}',b'{"action":"admin"}',b'not-json'):
        assert handler.handle(object(), frame) == b'{"error":"binding_unavailable"}'
    assert invoked == ["issued"]


def test_existing_tray_exposes_binding_action():
    from pathlib import Path
    from pc_agent.platform.windows.tray import _WindowsTray, _BINDING_COMMAND
    tray = _WindowsTray(Path("unused"))
    assert tray._menu_label(_BINDING_COMMAND) == "Привязать компьютер к Helpdesk"


@pytest.mark.skipif(__import__("os").name != "nt", reason="native Windows IPC client")
def test_tray_ipc_uses_close_cancellation_and_always_closes_handle(monkeypatch):
    import json
    from threading import Event
    from pc_agent.platform.windows import device_binding, sensor_pipe_listener
    import win32file
    stop = Event()
    calls = []
    handle = object()
    monkeypatch.setattr(device_binding, "connect_client_pipe", lambda **kwargs: handle)
    monkeypatch.setattr(win32file, "CloseHandle", lambda item: calls.append(("closed", item)))
    monkeypatch.setattr(sensor_pipe_listener, "_write_frame",
        lambda item, frame, cancel, deadline: calls.append(("write", cancel)))
    monkeypatch.setattr(sensor_pipe_listener, "_read_frame",
        lambda item, cancel, deadline: calls.append(("read", cancel)) or json.dumps(payload()).encode())
    device_binding.request_challenge_from_service(stop=stop)
    assert calls == [("write", stop), ("read", stop), ("closed", handle)]
    calls.clear()
    stop.set()
    with pytest.raises(device_binding.BindingUnavailable):
        device_binding.request_challenge_from_service(stop=stop)
    assert calls == []


def test_binding_dialog_refresh_copy_open_and_close_use_only_ephemeral_state(monkeypatch):
    tk = pytest.importorskip("tkinter")
    from tkinter import ttk
    from pc_agent.platform.windows import binding_dialog, device_binding
    widgets, callbacks, issued, opened, clipboard = [], [], [], [], []
    protocols = {}

    class Widget:
        def __init__(self, *args, **kwargs):
            self.options = kwargs
            widgets.append(self)
        def pack(self, **kwargs): pass
        def configure(self, **kwargs): self.options.update(kwargs)

    class Variable:
        def __init__(self, value=""): self.value = value
        def set(self, value): self.value = value

    def button(text):
        return next(item for item in widgets if item.options.get("text") == text)

    class Window:
        def title(self, value): pass
        def geometry(self, value): pass
        def resizable(self, *args): pass
        def protocol(self, name, callback): protocols[name] = callback
        def after(self, delay, callback): callbacks.append(callback)
        def clipboard_clear(self): clipboard.clear()
        def clipboard_append(self, value): clipboard.append(value)
        def destroy(self): pass
        def mainloop(self):
            assert button("Открыть Helpdesk").options["state"] == "disabled"
            callbacks.pop(0)()
            assert button("Открыть Helpdesk").options["state"] == "normal"
            button("Скопировать код").options["command"]()
            button("Открыть Helpdesk").options["command"]()
            assert clipboard == ["123-456"]
            assert opened == ["https://helpdesk.sosnadmin.local/app/requester/devices/link#code=123456"]
            button("Получить новый код").options["command"]()
            assert button("Скопировать код").options["state"] == "disabled"
            callbacks.pop(0)()
            assert len(issued) == 2
            protocols["WM_DELETE_WINDOW"]()
            assert all(cancel.is_set() for cancel in issued)
            # A previously scheduled callback is inert after closing.
            callbacks.pop(0)()
            assert callbacks == []

    class ImmediateThread:
        def __init__(self, *, target, **kwargs): self.target = target
        def start(self): self.target()

    def issue(*, stop):
        issued.append(stop)
        return device_binding.parse_challenge(payload())

    monkeypatch.setattr(tk, "Tk", Window)
    monkeypatch.setattr(tk, "StringVar", Variable)
    for name in ("Frame", "Label", "Button"):
        monkeypatch.setattr(ttk, name, Widget)
    monkeypatch.setattr(binding_dialog, "Thread", ImmediateThread)
    monkeypatch.setattr(binding_dialog, "request_challenge_from_service", issue)
    monkeypatch.setattr(binding_dialog.webbrowser, "open", lambda link: opened.append(link) or True)
    binding_dialog.show_binding_dialog()
