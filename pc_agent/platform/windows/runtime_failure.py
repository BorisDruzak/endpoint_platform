"""Write the bounded diagnostic for a failed Windows Core runtime."""

import re


# Generic single-insertion error in the pywin32 service message table.
_SERVICE_GENERIC_ERROR = 0xC00000FF
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}")


def _symbol(value: object) -> str:
    return value if isinstance(value, str) and _SYMBOL.fullmatch(value) else "unknown"


def report_unexpected_failure(stage: str, error: Exception) -> None:
    import win32evtlog

    # Connected coroutines can fail as an ExceptionGroup. Report the first
    # contained exception, without formatting the group, message or traceback.
    while isinstance(error, BaseExceptionGroup):
        error = error.exceptions[0]
    trace = error.__traceback__
    location = "unknown"
    if trace is not None:
        while trace.tb_next is not None:
            trace = trace.tb_next
        frame = trace.tb_frame
        module = _symbol(frame.f_globals.get("__name__"))
        function = _symbol(frame.f_code.co_name)
        location = f"{module}.{function}:{trace.tb_lineno}"
    message = (
        f"EndpointAgent Core runtime failure: stage={_symbol(stage)} "
        f"exception={_symbol(type(error).__name__)} location={location}"
    )
    source = win32evtlog.RegisterEventSource(None, "EndpointAgent")
    try:
        win32evtlog.ReportEvent(
            source, win32evtlog.EVENTLOG_ERROR_TYPE, 0, _SERVICE_GENERIC_ERROR,
            None, [message], None,
        )
    finally:
        win32evtlog.DeregisterEventSource(source)
