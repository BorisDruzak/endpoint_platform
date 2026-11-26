"""Keep Linux system programs on the host's dynamic loader search path."""

import os
import sys


def system_program_environment() -> dict[str, str] | None:
    if sys.platform != "linux" or not getattr(sys, "frozen", False):
        return None
    # Both Core and Launcher bundle libraries. PyInstaller can save the
    # Launcher's private path in ORIG when it starts Core.
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_LIBRARY_PATH_ORIG", None)
    return env
