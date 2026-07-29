"""Read-only, bounded collectors for fixed Device Context profiles."""

from .registry import ContextCapabilityError, execute_context_capability

__all__ = ["ContextCapabilityError", "execute_context_capability"]
