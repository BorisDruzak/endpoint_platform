"""Windows-only boundaries for the neutral Endpoint Agent runtime.

The modules in this package remain import-safe on non-Windows hosts so their
contracts can be tested without installing an SCM service.
"""

from .service import SERVICE_ACCOUNT, SERVICE_NAME

__all__ = ["SERVICE_ACCOUNT", "SERVICE_NAME"]
