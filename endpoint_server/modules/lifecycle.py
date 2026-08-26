"""Closed lifecycle transitions for immutable module versions."""

from __future__ import annotations

from collections.abc import Mapping


class ModuleLifecycleError(ValueError):
    """The requested version transition is outside the published lifecycle."""


_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "draft": frozenset({"validation_failed", "validated", "revoked"}),
    "validation_failed": frozenset({"validated", "revoked"}),
    "validated": frozenset({"lab_accepted", "validation_failed", "revoked"}),
    "lab_accepted": frozenset({"published", "revoked"}),
    "published": frozenset({"deprecated", "revoked"}),
    "deprecated": frozenset(),
    "revoked": frozenset(),
}


def transition_module_version(current: str, target: str) -> str:
    if target not in _TRANSITIONS.get(current, frozenset()):
        raise ModuleLifecycleError("module version lifecycle transition is not allowed")
    return target


__all__ = ["ModuleLifecycleError", "transition_module_version"]
