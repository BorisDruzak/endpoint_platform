#!/usr/bin/python3 -I
"""Run the selected credential-free Core native host as the browser user."""
import os
from pathlib import Path
import re
import subprocess
import sys


def main() -> int:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        return 78
    try:
        result = subprocess.run(
            ['/usr/lib/endpoint-agent/check-start-prerequisites', '--print-selected-version'],
            capture_output=True, check=True, timeout=5,
        )
        if len(result.stdout) > 128:
            return 78
        version = result.stdout.decode('ascii').strip()
        if re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version) is None:
            return 78
        executable = Path('/opt/endpoint-agent/versions') / version / 'endpoint-agent/endpoint-agent'
        os.execv(executable, [str(executable), '--linux-browser-bridge', *sys.argv[1:]])
    except (OSError, ValueError, subprocess.SubprocessError):
        return 78
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
