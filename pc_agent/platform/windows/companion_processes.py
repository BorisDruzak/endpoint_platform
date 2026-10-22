"""Stop exact installed companions without importing service or updater roles."""
from __future__ import annotations
import os
from .update_paths import WindowsUpdatePaths
_TRAY_EXECUTABLE_NAME = "EndpointAgentTray.exe"
_USER_SENSOR_EXECUTABLE_NAME = "EndpointUserSensor.exe"

def stop_tray_companions(paths: WindowsUpdatePaths | None = None) -> None:
    """Stop only fixed installed user companions before MSI replaces their files."""
    if os.name != "nt":
        return
    try:
        import win32api  # type: ignore[import-not-found]
        import win32con  # type: ignore[import-not-found]
        import win32event  # type: ignore[import-not-found]
        import win32process  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError("pywin32 is required to stop Endpoint Agent tray") from error

    install_root = (paths or WindowsUpdatePaths.production()).install_root
    expected = {
        os.path.normcase(os.path.normpath(str(install_root / name)))
        for name in (_TRAY_EXECUTABLE_NAME, _USER_SENSOR_EXECUTABLE_NAME)
    }
    access = (
        win32con.PROCESS_QUERY_LIMITED_INFORMATION
        | win32con.PROCESS_TERMINATE
        | win32con.SYNCHRONIZE
    )
    tray_handles = []
    for process_id in win32process.EnumProcesses():
        try:
            handle = win32api.OpenProcess(access, False, process_id)
        except win32api.error:
            continue
        try:
            image = os.path.normcase(
                os.path.normpath(win32process.GetModuleFileNameEx(handle, 0))
            )
        except win32api.error:
            handle.Close()
            continue
        if image in expected:
            tray_handles.append(handle)
        else:
            handle.Close()
    try:
        for handle in tray_handles:
            win32process.TerminateProcess(handle, 0)
        for handle in tray_handles:
            if win32event.WaitForSingleObject(handle, 15_000) != win32event.WAIT_OBJECT_0:
                raise RuntimeError("Endpoint Agent user companion did not stop before update")
    finally:
        for handle in tray_handles:
            handle.Close()
