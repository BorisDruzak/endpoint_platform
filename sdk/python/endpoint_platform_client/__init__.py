"""Safe, TLS-verifying client for Endpoint Platform Device Context APIs."""

from .client import EndpointPlatformClient
from .errors import (
    EndpointPlatformConfigurationError,
    EndpointPlatformError,
    EndpointPlatformInvalidRequest,
    EndpointPlatformMalformedResponse,
    EndpointPlatformNotFound,
    EndpointPlatformResponseError,
    EndpointPlatformUnavailable,
)
from .models import (
    BaselineHistory,
    Collection,
    CollectionDetails,
    ContextComparison,
    ContextProfileAvailability,
    ContextSnapshot,
    Device,
    DeviceContext,
    SafeContextProfile,
)

__all__ = [
    "BaselineHistory",
    "Collection",
    "CollectionDetails",
    "ContextComparison",
    "ContextProfileAvailability",
    "ContextSnapshot",
    "Device",
    "DeviceContext",
    "EndpointPlatformClient",
    "EndpointPlatformConfigurationError",
    "EndpointPlatformError",
    "EndpointPlatformInvalidRequest",
    "EndpointPlatformMalformedResponse",
    "EndpointPlatformNotFound",
    "EndpointPlatformResponseError",
    "EndpointPlatformUnavailable",
    "SafeContextProfile",
]
