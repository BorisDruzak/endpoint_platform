"""Temporary probe for validating endpoint_platform GitNexus refresh."""

GITNEXUS_ENDPOINT_PROBE_VERSION = "2026-08-16-v1"


def gitnexus_endpoint_update_probe() -> str:
    """Return the unique endpoint_platform GitNexus probe version."""
    return GITNEXUS_ENDPOINT_PROBE_VERSION


class GitNexusEndpointUpdateProbe:
    """Unique symbol used to verify endpoint_platform index refresh."""

    version = GITNEXUS_ENDPOINT_PROBE_VERSION
