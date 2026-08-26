"""Fail-closed target policy for network probe capabilities."""

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


class NetworkTargetPolicyError(ValueError):
    """Stable denial code for a target that cannot be probed."""


def _normalized_cidrs(values: Iterable[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    result: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ValueError("allowed CIDR must be a canonical network") from error
        result.append(network)
    return tuple(result)


def _normalized_suffixes(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("allowed suffix must be a trimmed domain suffix")
        suffix = value.lower()
        if _SUFFIX_PATTERN.fullmatch(suffix) is None:
            raise ValueError("allowed suffix must be a dotted domain suffix")
        normalized.append(suffix)
    return tuple(dict.fromkeys(normalized))


def _parse_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | str:
    if not isinstance(value, str) or value != value.strip() or "://" in value or "/" in value or "@" in value:
        raise NetworkTargetPolicyError("network_target_invalid")
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        hostname = value.lower().rstrip(".")
        if _HOSTNAME_PATTERN.fullmatch(value) is None:
            raise NetworkTargetPolicyError("network_target_invalid")
        return hostname


def _is_forbidden_address(value: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if value.is_loopback or value.is_unspecified or value.is_multicast or value.is_link_local:
        return True
    return isinstance(value, ipaddress.IPv4Address) and value == ipaddress.IPv4Address("255.255.255.255")


@dataclass(frozen=True, slots=True)
class NetworkTargetPolicyV1:
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_suffixes: tuple[str, ...]

    @classmethod
    def from_values(
        cls, *, allowed_cidrs: Iterable[str], allowed_suffixes: Iterable[str]
    ) -> "NetworkTargetPolicyV1":
        return cls(
            allowed_cidrs=_normalized_cidrs(allowed_cidrs),
            allowed_suffixes=_normalized_suffixes(allowed_suffixes),
        )

    def require_allowed(self, target: str) -> None:
        if not self.allowed_cidrs and not self.allowed_suffixes:
            raise NetworkTargetPolicyError("network_target_policy_not_configured")
        parsed = _parse_target(target)
        if isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if _is_forbidden_address(parsed):
                raise NetworkTargetPolicyError("network_target_forbidden_address")
            if any(parsed in network for network in self.allowed_cidrs):
                return
            raise NetworkTargetPolicyError("network_target_disallowed")
        if any(parsed.endswith(suffix) and parsed != suffix[1:] for suffix in self.allowed_suffixes):
            return
        raise NetworkTargetPolicyError("network_target_disallowed")


__all__ = ["NetworkTargetPolicyError", "NetworkTargetPolicyV1"]
