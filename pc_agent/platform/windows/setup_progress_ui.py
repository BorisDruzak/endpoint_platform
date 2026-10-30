"""Native Setup view. Only this thread owns HWNDs; installer work stays put."""

from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import os
from pathlib import Path
import threading
import time

from pc_agent.setup_progress import SetupProgress


class SetupProgressWindow:
    def __init__(self, result_path: Path):
        self.result_path = result_path
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._last = SetupProgress("PREFLIGHT", "running")
        self._finished = False
        self._failure = None
        self._started = time.monotonic()
        self._thread = threading.Thread(
            target=self._thread_main, name="SetupProgressUI", daemon=True
        )

    def start(self):
        self._thread.start()
        if not self._ready.wait(10) or self._failure is not None:
            raise OSError("Setup progress window unavailable") from self._failure

    def update(self, event: SetupProgress):
        with self._lock:
            self._last = event

    def finish(self, code: int):
        with self._lock:
            event = self._last
            status = "success" if code in (0, 10) else "error"
            self._last = SetupProgress(event.stage, status, event.detail, code)
            self._finished = True

    def wait_closed(self):
        while not self._closed.wait(0.25):
            pass
        if self._failure is not None:
            raise OSError("Setup progress window failed") from self._failure

    def _thread_main(self):
        try:
            self._native_loop()
        except Exception as error:
            self._failure = error
        finally:
            self._ready.set()
            self._closed.set()

    def _native_loop(self):
        if os.name != "nt":
            raise OSError("Windows desktop required")
        user = ctypes.WinDLL("user32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        gdi = ctypes.WinDLL("gdi32", use_last_error=True)
        common = ctypes.WinDLL("comctl32", use_last_error=True)
        proc = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

        class WindowClass(ctypes.Structure):
            _fields_ = [
                ("style", w.UINT),
                ("procedure", proc),
                ("class_extra", ctypes.c_int),
                ("window_extra", ctypes.c_int),
                ("instance", w.HINSTANCE),
                ("icon", w.HICON),
                ("cursor", w.HANDLE),
                ("background", w.HBRUSH),
                ("menu", w.LPCWSTR),
                ("name", w.LPCWSTR),
            ]

        def bind(dll, name, args, result):
            function = getattr(dll, name)
            function.argtypes = args
            function.restype = result
            return function

        create = bind(
            user,
            "CreateWindowExW",
            [
                w.DWORD,
                w.LPCWSTR,
                w.LPCWSTR,
                w.DWORD,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                w.HWND,
                w.HMENU,
                w.HINSTANCE,
                w.LPVOID,
            ],
            w.HWND,
        )
        default = bind(
            user,
            "DefWindowProcW",
            [w.HWND, w.UINT, w.WPARAM, w.LPARAM],
            ctypes.c_ssize_t,
        )
        register = bind(user, "RegisterClassW", [ctypes.POINTER(WindowClass)], w.ATOM)
        unregister = bind(user, "UnregisterClassW", [w.LPCWSTR, w.HINSTANCE], w.BOOL)
        send = bind(
            user, "SendMessageW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM], ctypes.c_ssize_t
        )
        text = bind(user, "SetWindowTextW", [w.HWND, w.LPCWSTR], w.BOOL)
        destroy = bind(user, "DestroyWindow", [w.HWND], w.BOOL)
        enable = bind(user, "EnableWindow", [w.HWND, w.BOOL], w.BOOL)
        system_menu = bind(user, "GetSystemMenu", [w.HWND, w.BOOL], w.HMENU)
        menu_item = bind(user, "EnableMenuItem", [w.HMENU, w.UINT, w.UINT], w.BOOL)
        timer = bind(
            user,
            "SetTimer",
            [w.HWND, ctypes.c_size_t, w.UINT, w.LPVOID],
            ctypes.c_size_t,
        )
        kill_timer = bind(user, "KillTimer", [w.HWND, ctypes.c_size_t], w.BOOL)
        get_message = bind(
            user,
            "GetMessageW",
            [ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT],
            ctypes.c_int,
        )
        dispatch = bind(
            user, "DispatchMessageW", [ctypes.POINTER(w.MSG)], ctypes.c_ssize_t
        )
        translate = bind(user, "TranslateMessage", [ctypes.POINTER(w.MSG)], w.BOOL)
        dialog_message = bind(
            user, "IsDialogMessageW", [w.HWND, ctypes.POINTER(w.MSG)], w.BOOL
        )
        update_window = bind(user, "UpdateWindow", [w.HWND], w.BOOL)
        quit_message = bind(user, "PostQuitMessage", [ctypes.c_int], None)
        show = bind(user, "ShowWindow", [w.HWND, ctypes.c_int], w.BOOL)
        foreground = bind(user, "SetForegroundWindow", [w.HWND], w.BOOL)
        instance = bind(kernel, "GetModuleHandleW", [w.LPCWSTR], w.HINSTANCE)(None)
        cursor = bind(user, "LoadCursorW", [w.HINSTANCE, w.LPVOID], w.HANDLE)(
            None, ctypes.c_void_p(32512)
        )
        brush = bind(user, "GetSysColorBrush", [ctypes.c_int], w.HBRUSH)(5)
        font = bind(gdi, "GetStockObject", [ctypes.c_int], w.HANDLE)(17)
        common.InitCommonControls()
        controls = {}
        finished_rendered = False
        last_rendered = None

        def paint():
            nonlocal finished_rendered, last_rendered
            with self._lock:
                event, finished = self._last, self._finished
            if event != last_rendered:
                text(controls["stage"], event.title)
                text(controls["message"], event.message)
                last_rendered = event
            if finished:
                text(controls["elapsed"], f"Код результата: {event.code}")
                if not finished_rendered:
                    send(controls["bar"], 0x040A, 0, 0)  # PBM_SETMARQUEE off
                    send(
                        controls["bar"],
                        0x0402,
                        100 if event.status == "success" else 0,
                        0,
                    )
                    text(
                        controls["heading"],
                        "Установка завершена"
                        if event.status == "success"
                        else "Требуется действие",
                    )
                    enable(controls["close"], True)
                    menu_item(system_menu(hwnd, False), 0xF060, 0)
                    foreground(hwnd)
                    finished_rendered = True
            else:
                seconds = int(time.monotonic() - self._started)
                text(
                    controls["elapsed"],
                    f"Выполняется установка · прошло {seconds // 60:02d}:{seconds % 60:02d}",
                )

        @proc
        def procedure(window, message, wp, lp):
            # ctypes callbacks must not let exceptions unwind through Windows.
            try:
                if message == 0x0113 and controls:  # WM_TIMER
                    paint()
                    return 0
                if message == 0x0010 or (message == 0x0111 and (wp & 0xFFFF) in (1, 2)):
                    with self._lock:
                        can_close = self._finished
                    if can_close:
                        destroy(window)
                    return 0
                if message == 0x0002:
                    quit_message(0)
                    return 0
            except Exception as error:
                self._failure = error
                destroy(window)
                return 0
            return default(window, message, wp, lp)

        class_name = f"EndpointSetupProgress-{os.getpid()}-{threading.get_ident()}"
        window_class = WindowClass(
            0, procedure, 0, 0, instance, None, cursor, brush, None, class_name
        )
        if not register(ctypes.byref(window_class)):
            raise ctypes.WinError(ctypes.get_last_error())
        hwnd = None
        try:
            hwnd = create(
                0,
                class_name,
                "Endpoint Agent — установка",
                0x00C80000,
                0x80000000,
                0x80000000,
                680,
                420,
                None,
                None,
                instance,
                None,
            )
            if not hwnd:
                raise ctypes.WinError(ctypes.get_last_error())

            def child(name, kind, label, x, y, width, height, extra=0, identifier=0):
                control = create(
                    0,
                    kind,
                    label,
                    0x50000000 | extra,
                    x,
                    y,
                    width,
                    height,
                    hwnd,
                    identifier,
                    instance,
                    None,
                )
                if not control:
                    raise ctypes.WinError(ctypes.get_last_error())
                send(control, 0x0030, font, 1)
                controls[name] = control

            child("heading", "STATIC", "Установка Endpoint Agent", 24, 22, 620, 25)
            child("stage", "STATIC", "Проверка компьютера", 24, 63, 620, 22)
            child("bar", "msctls_progress32", "", 24, 96, 620, 20, 8)
            child("message", "STATIC", "Подготовка…", 24, 134, 620, 90)
            child("elapsed", "STATIC", "", 24, 236, 620, 22)
            child(
                "logs",
                "STATIC",
                f"Результат и журналы:\n{self.result_path.parent}",
                24,
                271,
                620,
                48,
            )
            child("close", "BUTTON", "Закрыть", 530, 328, 114, 30, 0x10001, 1)
            enable(controls["close"], False)
            menu_item(system_menu(hwnd, False), 0xF060, 1)
            send(controls["bar"], 0x040A, 1, 40)
            if not timer(hwnd, 1, 150, None):
                raise ctypes.WinError(ctypes.get_last_error())
            paint()
            show(hwnd, 5)
            update_window(hwnd)
            foreground(hwnd)
            self._ready.set()
            message = w.MSG()
            while True:
                state = get_message(ctypes.byref(message), None, 0, 0)
                if state == -1:
                    raise ctypes.WinError(ctypes.get_last_error())
                if state == 0:
                    break
                if not dialog_message(hwnd, ctypes.byref(message)):
                    translate(ctypes.byref(message))
                    dispatch(ctypes.byref(message))
        finally:
            if hwnd:
                kill_timer(hwnd, 1)
                destroy(hwnd)
            unregister(class_name, instance)
