"""Audit-domain exceptions shared by persistence and service layers."""


class AuditMutationError(RuntimeError):
    """Raised when code tries to update or delete an append-only audit event."""
