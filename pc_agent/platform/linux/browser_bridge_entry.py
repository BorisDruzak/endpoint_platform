"""Credential-free binary stdio entrypoint invoked only by an interactive browser."""
from collections.abc import Sequence
import os
import sys

from pc_agent.browser_identity import load_packaged_extension_id
from .browser_bridge import BrowserBridgeInvocationError, run_native_bridge


def main(arguments: Sequence[str] | None = None) -> int:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        return 1
    try:
        run_native_bridge(stdin=sys.stdin.buffer, stdout=sys.stdout.buffer,
            arguments=list(sys.argv[1:] if arguments is None else arguments),
            expected_extension_id=load_packaged_extension_id())
    except (BrowserBridgeInvocationError, OSError, ValueError):
        return 2
    return 0
