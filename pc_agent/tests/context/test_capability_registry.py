from __future__ import annotations

import pytest

from pc_agent.context_profiles.registry import ContextCapabilityError
from pc_agent.core.registry import CONTEXT_COLLECTION_CAPABILITIES, execute_context_capability


def test_only_fixed_context_capabilities_resolve(fake_probe) -> None:
    """A capability registry change must never make a caller-selected action executable."""
    expected = {
        "context.baseline.collect": "baseline_v1",
        "context.health.collect": "health_v1",
        "context.network.collect": "network_v1",
    }

    assert CONTEXT_COLLECTION_CAPABILITIES == frozenset(
        {
            "context.baseline.collect",
            "context.health.collect",
            "context.network.collect",
            "context.diagnostic.collect",
        }
    )
    for capability, profile in expected.items():
        assert execute_context_capability(capability, {}, probe=fake_probe).profile == profile

    with pytest.raises(ContextCapabilityError):
        execute_context_capability("context.run_shell", {"argv": ["id"]}, probe=fake_probe)


@pytest.mark.parametrize(
    "capability",
    [
        "context.baseline.collect",
        "context.health.collect",
        "context.network.collect",
    ],
)
def test_scheduled_context_profiles_accept_only_an_empty_object(fake_probe, capability) -> None:
    """A profile must not turn arbitrary command parameters into collector input."""
    with pytest.raises(ContextCapabilityError):
        execute_context_capability(capability, {"unexpected": True}, probe=fake_probe)


@pytest.mark.parametrize(
    "parameters",
    [{"reason": "manual request", "extra": "not allowed"}, {"reason": "x" * 257}, {"reason": ""}],
)
def test_diagnostic_accepts_only_one_bounded_reason(fake_probe, parameters) -> None:
    """Removing the diagnostic input guard would permit unbounded or arbitrary payloads."""
    with pytest.raises(ContextCapabilityError):
        execute_context_capability("context.diagnostic.collect", parameters, probe=fake_probe)


def test_diagnostic_maps_the_only_accepted_parameter_to_the_profile(fake_probe) -> None:
    result = execute_context_capability(
        "context.diagnostic.collect", {"reason": "manual request"}, probe=fake_probe
    )

    assert result.profile == "diagnostic_v1"
    assert result.sections.reason == "manual request"
