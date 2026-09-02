"""Agent-local fail-closed policy for concrete network probe targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable


_HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?\Z"
)
_SUFFIX_PATTERN = re.compile(
    r"^\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


class NetworkProbeDenied(ValueError):
    """Stable policy denial suitable for the agent result envelope."""


def _networks(values: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            parsed.append(ipaddress.ip_network(value, strict=True))
        except ValueError as error:
            raise ValueError("allowed CIDR must be a canonical network") from error
    return tuple(parsed)


def _suffixes(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or value != value.strip() or _SUFFIX_PATTERN.fullmatch(value.lower()) is None:
            raise ValueError("allowed suffix must be a dotted domain suffix")
        result.append(value.lower())
    return tuple(dict.fromkeys(result))


@dataclass(frozen=True, slots=True)
class AgentNetworkProbePolicy:
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_suffixes: tuple[str, ...]

    @classmethod
    def from_values(
        cls, *, allowed_cidrs: Iterable[str], allowed_suffixes: Iterable[str]
    ) -> "AgentNetworkProbePolicy":
        return cls(_networks(allowed_cidrs), _suffixes(allowed_suffixes))

    def require_allowed(self, target: str) -> None:
        if not self.allowed_cidrs and not self.allowed_suffixes:
            raise NetworkProbeDenied("network_target_policy_not_configured")
        if not isinstance(target, str) or target != target.strip() or "://" in target or "/" in target or "@" in target:
            raise NetworkProbeDenied("network_target_invalid")
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            hostname = target.lower().rstrip(".")
            if _HOSTNAME_PATTERN.fullmatch(target) is None:
                raise NetworkProbeDenied("network_target_invalid")
            if any(hostname.endswith(suffix) and hostname != suffix[1:] for suffix in self.allowed_suffixes):
                return
            raise NetworkProbeDenied("network_target_disallowed")
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local or (
            isinstance(address, ipaddress.IPv4Address) and address == ipaddress.IPv4Address("255.255.255.255")
        ):
            raise NetworkProbeDenied("network_target_forbidden_address")
        if any(address in network for network in self.allowed_cidrs):
            return
        raise NetworkProbeDenied("network_target_disallowed")
