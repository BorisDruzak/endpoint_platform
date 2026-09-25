"""Binary-stdio entrypoint for the Endpoint Native Messaging host."""

from __future__ import annotations

import os
from pathlib import Path
import re
import sys

from pc_agent.platform.windows.browser_bridge import (
    BrowserBridgeInvocationError,
    run_native_bridge,
)


def _extension_id() -> str:
    if getattr(sys, "frozen", False):
        bundle_root = Path(sys._MEIPASS)
    else:
        bundle_root = Path(__file__).resolve().parents[3]
    identity_path = bundle_root / "browser_sensor" / "extension-id.txt"
    extension_id = identity_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("invalid packaged Browser Sensor identity")
    return extension_id


def main() -> int:
    if os.name == "nt":
        import msvcrt

        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    try:
        run_native_bridge(
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            arguments=sys.argv[1:],
            expected_extension_id=_extension_id(),
        )
    except BrowserBridgeInvocationError:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
