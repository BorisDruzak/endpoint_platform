"""Redacted error types raised by the Endpoint Platform service client."""

from __future__ import annotations


class EndpointPlatformError(RuntimeError):
    """Base class for errors that never render upstream payloads or credentials."""


class EndpointPlatformConfigurationError(EndpointPlatformError):
    """The local token, CA bundle, or HTTPS configuration is unusable."""

    def __init__(self) -> None:
        super().__init__("Endpoint Platform client configuration is invalid")


class EndpointPlatformUnavailable(EndpointPlatformError):
    """The service could not be reached after bounded read attempts."""

    def __init__(self) -> None:
        super().__init__("Endpoint Platform service is unavailable")


class EndpointPlatformResponseError(EndpointPlatformError):
    """The service returned a non-success HTTP response without exposing its body."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Endpoint Platform service returned HTTP {status_code}")


class EndpointPlatformMalformedResponse(EndpointPlatformError):
    """The service response was not a valid safe Device Context projection."""

    def __init__(self) -> None:
        super().__init__("Endpoint Platform service returned an invalid safe response")


class EndpointPlatformInvalidRequest(EndpointPlatformError):
    """The caller attempted an operation outside the safe SDK boundary."""

    def __init__(self) -> None:
        super().__init__("Endpoint Platform request is outside the safe client boundary")


class EndpointPlatformNotFound(EndpointPlatformError):
    """A safe service resource was not found."""

    def __init__(self) -> None:
        super().__init__("Endpoint Platform resource was not found")
