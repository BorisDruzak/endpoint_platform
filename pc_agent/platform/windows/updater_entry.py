"""Dedicated fixed SCM entry for the privileged offline updater."""
from __future__ import annotations

import json
import sys
from collections.abc import Sequence

from pc_agent.platform.windows.updater_service import run_windows_updater_service


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ['--updater-service']:
        return run_windows_updater_service()
    if args == ['--verify-offline']:
        # Exercise native imports in the packaged runtime without dispatching
        # SCM or opening any device credential, pending path or selector.
        if sys.platform == 'win32':
            import servicemanager
            import win32serviceutil
            import win32security
            import win32file
            import ntsecuritycon
        from pc_agent.platform.windows import tray_status
        print(json.dumps({'offline_worker_imports': 'verified'}))
        return 0
    raise ValueError('Offline updater accepts only fixed SCM or verification modes')


if __name__ == '__main__':
    raise SystemExit(main())
