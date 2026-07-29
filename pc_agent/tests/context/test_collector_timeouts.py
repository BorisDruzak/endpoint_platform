from __future__ import annotations

import pytest

from pc_agent.context_profiles.baseline import collect_baseline
from pc_agent.context_profiles.diagnostic import collect_diagnostic
from pc_agent.context_profiles.health import collect_health
from pc_agent.context_profiles.network import collect_network

from .conftest import FIXED_TIME, FakeProbe


@pytest.mark.parametrize(
    ("collector", "kwargs"),
    [
        (collect_baseline, {}),
        (collect_health, {}),
        (collect_network, {}),
        (collect_diagnostic, {"reason": "operator investigation"}),
    ],
)
def test_collectors_return_valid_envelopes_when_local_commands_time_out(collector, kwargs) -> None:
    """A normalized probe timeout never escapes any context profile collector."""
    probe = FakeProbe()

    def timed_out(*args, **kwargs):
        raise TimeoutError("context probe command timed out")

    probe.run = timed_out
    result = collector(probe, collected_at=FIXED_TIME, **kwargs)

    assert result.collected_at == FIXED_TIME
    assert "command_timed_out" in result.warnings
