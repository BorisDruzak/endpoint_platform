"""Exact profile mapping; callers cannot select a command or collector dynamically."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from endpoint_contracts.context import DeviceContextEnvelopeV1

from .baseline import collect_baseline
from .diagnostic import collect_diagnostic
from .health import collect_health
from .network import collect_network


class ContextCapabilityError(ValueError):
    """Raised for a capability or parameter shape outside the fixed allowlist."""


def execute_context_capability(
    capability: str,
    parameters: Mapping[str, object],
    probe: object,
    *,
    collected_at: datetime | None = None,
) -> DeviceContextEnvelopeV1:
    if not isinstance(parameters, Mapping):
        raise ContextCapabilityError("context parameters must be an object")
    if capability == "context.baseline.collect":
        _require_empty(parameters)
        return collect_baseline(probe, collected_at=collected_at)
    if capability == "context.health.collect":
        _require_empty(parameters)
        return collect_health(probe, collected_at=collected_at)
    if capability == "context.network.collect":
        _require_empty(parameters)
        return collect_network(probe, collected_at=collected_at)
    if capability == "context.diagnostic.collect":
        if set(parameters) != {"reason"} or not isinstance(parameters["reason"], str):
            raise ContextCapabilityError("diagnostic collection requires only a string reason")
        return collect_diagnostic(probe, reason=parameters["reason"], collected_at=collected_at)
    raise ContextCapabilityError("unsupported context capability")


def _require_empty(parameters: Mapping[str, object]) -> None:
    if parameters:
        raise ContextCapabilityError("this context capability accepts no parameters")
