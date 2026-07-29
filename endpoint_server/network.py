"""Application-owned client address resolution with explicit proxy trust."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import Request


def observed_client_address(request: Request) -> IPv4Address | IPv6Address:
    """Resolve one client address without trusting caller-controlled forwarding."""
    if request.client is None:
        raise ValueError("observed peer is unavailable")
    try:
        peer = ip_address(request.client.host)
    except ValueError as error:
        raise ValueError("observed peer is invalid") from error
    if not any(
        peer in network for network in request.app.state.settings.trusted_proxy_cidrs
    ):
        return peer

    forwarded_values = request.headers.getlist("x-forwarded-for")
    forwarded = forwarded_values[0] if len(forwarded_values) == 1 else None
    if (
        forwarded is None
        or not forwarded
        or forwarded != forwarded.strip()
        or "," in forwarded
        or any(character.isspace() for character in forwarded)
    ):
        raise ValueError("trusted proxy supplied an invalid client address")
    try:
        return ip_address(forwarded)
    except ValueError as error:
        raise ValueError("trusted proxy supplied an invalid client address") from error
