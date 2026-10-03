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
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from pc_agent.platform.windows.selector_migration import _is_msi_owned_runtime
        from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
        # Cover the conditional MSI-owned rollback path as it executes inside
        # the actual archive. These temporary bytes are never an executable
        # release and never enter the production pending or selector paths.
        with TemporaryDirectory(prefix='endpoint-offline-check-') as temporary:
            root = Path(temporary)
            paths = WindowsUpdatePaths(root / 'install', root / 'updates' / 'pending.json')
            runtime = paths.versions_root / '0.0.1'
            runtime.mkdir(parents=True)
            (runtime / 'pc_agent.exe').write_bytes(b'offline path validation fixture')
            (runtime / '.endpoint-msi-runtime.json').write_text(json.dumps({
                'schema_version': 1, 'version': '0.0.1',
                'component_guid': 'E43B1790-43B8-4B08-A8F9-79B535026121'}), encoding='utf-8')
            if not _is_msi_owned_runtime(paths, '0.0.1'):
                raise ValueError('Offline MSI-owned runtime validation failed')
        print(json.dumps({'offline_worker_imports': 'verified', 'msi_owned_validation': 'verified'}))
        return 0
    raise ValueError('Offline updater accepts only fixed SCM or verification modes')


if __name__ == '__main__':
    raise SystemExit(main())
