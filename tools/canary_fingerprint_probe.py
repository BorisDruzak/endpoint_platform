"""Print the canonical hardware fingerprint for a Windows canary host."""

from __future__ import annotations

from collections.abc import Callable

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint


def hardware_fingerprint(
    probe: Callable[[], object] = collect_device_fingerprint,
) -> str:
    """Return the enrollment-compatible fingerprint collected by *probe*."""
    return _derive_hardware_fingerprint(probe)


def main() -> int:
    print(hardware_fingerprint())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
