"""Fixed filesystem identity for the privileged Windows update worker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .service_control import UPDATER_SERVICE_NAME


def _native_folder(folder_id: int) -> Path:
    """Resolve a machine folder without trusting inherited environment values."""
    import ctypes
    from ctypes import wintypes

    query = ctypes.WinDLL("shell32", use_last_error=True).SHGetFolderPathW
    query.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR]
    query.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(260)
    result = query(None, folder_id, None, 0, buffer)
    if result != 0 or not buffer.value:
        raise OSError(f"Native machine folder resolution failed: {folder_id}: {result}")
    path = Path(buffer.value)
    if not path.is_absolute():
        raise ValueError("Native machine folder is not absolute")
    return path


INSTALL_ROOT = Path(r"C:\Program Files\Endpoint Platform\Agent")
PENDING_UPDATE_PATH = Path(
    r"C:\ProgramData\Endpoint Platform\Agent\updates\pending_update.json"
)
UPDATE_EXECUTABLE_NAME = "pc_agent.exe"


@dataclass(frozen=True, slots=True)
class WindowsUpdatePaths:
    """The only writable request and installation locations accepted by the worker.

    Constructor overrides exist solely for hermetic tests; the SCM entrypoint uses
    :meth:`production` and therefore has no caller-controlled path arguments.
    """

    install_root: Path = INSTALL_ROOT
    pending_path: Path = PENDING_UPDATE_PATH

    @classmethod
    def production(cls) -> "WindowsUpdatePaths":
        return cls(
            _native_folder(0x26) / "Endpoint Platform" / "Agent",
            _native_folder(0x23) / "Endpoint Platform" / "Agent" / "updates" / "pending_update.json",
        )

    @property
    def updates_root(self) -> Path:
        return self.pending_path.parent

    @property
    def downloads_root(self) -> Path:
        return self.updates_root / "downloads"

    @property
    def versions_root(self) -> Path:
        return self.install_root / "versions"

    @property
    def current_path(self) -> Path:
        return self.install_root / "current.json"

    @property
    def previous_path(self) -> Path:
        return self.install_root / "previous.json"

    @property
    def restore_path(self) -> Path:
        return self.install_root / "current-restore.json"

    @property
    def transition_path(self) -> Path:
        return self.install_root / "selector-transition.json"


__all__ = [
    "INSTALL_ROOT",
    "PENDING_UPDATE_PATH",
    "UPDATE_EXECUTABLE_NAME",
    "UPDATER_SERVICE_NAME",
    "WindowsUpdatePaths",
]
