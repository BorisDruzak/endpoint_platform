"""Fixed filesystem identity for the privileged Windows update worker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .service_control import UPDATER_SERVICE_NAME


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
        return cls(INSTALL_ROOT, PENDING_UPDATE_PATH)

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


__all__ = [
    "INSTALL_ROOT",
    "PENDING_UPDATE_PATH",
    "UPDATE_EXECUTABLE_NAME",
    "UPDATER_SERVICE_NAME",
    "WindowsUpdatePaths",
]
