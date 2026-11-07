"""Packaged installer host with separate native and notification-only modes."""
from __future__ import annotations
from typing import Sequence
from pc_agent.platform.windows.installer_native_entry import (
    WindowsUpdatePaths, add_installer_arguments, run_installer_args, _parser,
)


def main(argv: Sequence[str] | None = None) -> int:
    from pc_agent.platform.windows.installation_notification import notification_main
    notification = notification_main(argv)
    if notification is not None:
        return notification
    result = run_installer_args(_parser().parse_args(argv))
    if result is None:
        raise ValueError("unsupported installer host mode")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
