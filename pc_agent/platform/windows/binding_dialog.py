"""Modal binding view inside the existing tray executable; no credentials or disk state."""
from datetime import UTC, datetime
from queue import Empty, Queue
from threading import Event, Thread
import webbrowser

from .device_binding import DEFAULT_BINDING_ORIGIN, BindingUnavailable, helpdesk_link, request_challenge_from_service


def show_binding_dialog(*, binding_origin: str = DEFAULT_BINDING_ORIGIN):
    import tkinter as tk
    from tkinter import ttk

    window = tk.Tk()
    window.title("Привязать компьютер к Helpdesk")
    window.geometry("460x280")
    window.resizable(False, False)
    panel = ttk.Frame(window, padding=24)
    panel.pack(fill="both", expand=True)
    ttk.Label(panel, text="Код привязки", font=("Segoe UI", 13)).pack(pady=(0,12))
    code_text = tk.StringVar(value="Получение кода…")
    ttk.Label(panel, textvariable=code_text, font=("Segoe UI", 28)).pack()
    status = tk.StringVar(value="")
    ttk.Label(panel, textvariable=status, wraplength=400).pack(pady=12)
    actions = ttk.Frame(panel)
    actions.pack(fill="x")
    result = Queue()
    closed = Event()
    state = {"challenge":None, "busy":False}

    def close():
        closed.set()
        state["challenge"] = None
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", close)

    def valid_challenge():
        challenge = state["challenge"]
        return challenge if challenge and challenge.expires_at > datetime.now(UTC) else None

    def open_helpdesk():
        challenge = valid_challenge()
        if not challenge:
            return
        try:
            if not webbrowser.open(helpdesk_link(challenge, origin=binding_origin)):
                raise BindingUnavailable()
        except Exception:
            status.set("Не удалось открыть браузер. Введите код в Helpdesk вручную.")

    def copy_code():
        challenge = valid_challenge()
        if challenge:
            window.clipboard_clear()
            window.clipboard_append(challenge.display_code)
            status.set("Код скопирован. Он действует до указанного срока.")

    open_button = ttk.Button(actions, text="Открыть Helpdesk", command=open_helpdesk, state="disabled")
    open_button.pack(side="left")
    copy_button = ttk.Button(actions, text="Скопировать код", command=copy_code, state="disabled")
    copy_button.pack(side="right")

    def refresh():
        if state["busy"]:
            return
        state.update(challenge=None, busy=True)
        code_text.set("Получение кода…")
        status.set("")
        refresh_button.configure(state="disabled")
        open_button.configure(state="disabled")
        copy_button.configure(state="disabled")

        def request():
            try:
                challenge = request_challenge_from_service(stop=closed)
            except Exception:
                challenge = None
            if not closed.is_set():
                result.put(challenge)
        Thread(target=request, name="EndpointBindingTray", daemon=True).start()

    refresh_button = ttk.Button(panel, text="Получить новый код", command=refresh)
    refresh_button.pack(pady=12)

    def poll():
        if closed.is_set():
            return
        try:
            challenge = result.get_nowait()
            state.update(challenge=challenge, busy=False)
            refresh_button.configure(state="normal")
            if challenge:
                code_text.set(challenge.display_code)
                status.set("Код действует 10 минут. Введите его в Helpdesk, чтобы привязать компьютер.")
                open_button.configure(state="normal")
                copy_button.configure(state="normal")
            else:
                code_text.set("Код недоступен")
                status.set("Проверьте подключение Endpoint Agent. Попробуйте позже: частые запросы временно ограничиваются.")
        except Empty:
            pass
        if state["challenge"] and not valid_challenge():
            state["challenge"] = None
            code_text.set("Код истёк")
            status.set("Получите новый код.")
            open_button.configure(state="disabled")
            copy_button.configure(state="disabled")
        window.after(250, poll)

    refresh()
    window.after(250, poll)
    window.mainloop()
    closed.set()
    state["challenge"] = None
    while not result.empty():
        result.get_nowait()
