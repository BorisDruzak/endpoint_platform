"""Contract tests for the standalone canary fingerprint probe."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = REPOSITORY_ROOT / "tools" / "canary_fingerprint_probe.py"


def _load_probe_module():
    spec = importlib.util.spec_from_file_location("canary_fingerprint_probe", PROBE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_canary_fingerprint_probe_uses_canonical_derivation() -> None:
    """The standalone probe must emit the same identity value as enrollment."""

    def probe() -> dict[str, str]:
        return {"serial_number": "CANARY-001", "mac_address": "00:11:22:33:44:55"}

    module = _load_probe_module()

    assert module.hardware_fingerprint(probe) == _derive_hardware_fingerprint(probe)


def test_canary_fingerprint_spec_uses_tracked_entrypoint() -> None:
    """The frozen probe must not depend on an untracked local script."""
    spec = (REPOSITORY_ROOT / "endpoint-canary-fingerprint-probe.spec").read_text(
        encoding="utf-8"
    )

    assert ".canary_fingerprint_probe.py" not in spec
    assert 'os.path.join(SPECPATH, "tools", "canary_fingerprint_probe.py")' in spec
