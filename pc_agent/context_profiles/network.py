"""Route-aware network profile without any connectivity probing."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json

from endpoint_contracts.context import DeviceContextNetworkV1

from .probe import IP_ADDRESS_COMMAND, IP_DEFAULT_ROUTE_COMMAND
from .stable_keys import bounded_text


def collect_network(probe: object, *, collected_at: datetime | None = None) -> DeviceContextNetworkV1:
    if _is_windows(probe):
        return _collect_windows_network(probe, collected_at=collected_at)
    warnings: list[str] = []
    route = _default_route(probe, warnings)
    interfaces = _interfaces(probe, warnings)
    return DeviceContextNetworkV1(
        schema_version="device_context_v1",
        profile="network_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={"default_route": route, "interfaces": interfaces},
        warnings=list(dict.fromkeys(warnings))[:16],
    )


def _collect_windows_network(probe: object, *, collected_at: datetime | None) -> DeviceContextNetworkV1:
    from pc_agent.platform.windows.network import collect_default_route, collect_network_interfaces

    return DeviceContextNetworkV1(
        schema_version="device_context_v1",
        profile="network_v1",
        collected_at=collected_at or datetime.now(timezone.utc),
        sections={"default_route": collect_default_route(probe), "interfaces": collect_network_interfaces(probe)},
        warnings=[],
    )


def _is_windows(probe: object) -> bool:
    from pc_agent.platform.windows.identity import is_windows_context

    return is_windows_context(probe)


def _run_json(probe: object, command: tuple[str, ...], warnings: list[str]) -> object:
    try:
        return json.loads(str(probe.run(command, 2.0, 32_768)))
    except TimeoutError:
        warnings.append("command_timed_out")
    except (OSError, ValueError, TypeError):
        warnings.append("command_failed")
    return []


def _default_route(probe: object, warnings: list[str]) -> dict[str, str | None]:
    records = _run_json(probe, IP_DEFAULT_ROUTE_COMMAND, warnings)
    if isinstance(records, list):
        for record in records:
            if isinstance(record, Mapping) and record.get("dev"):
                return {
                    "interface": bounded_text(record.get("dev"), fallback="unknown", limit=64),
                    "gateway": bounded_text(record.get("gateway"), fallback="", limit=64) or None,
                }
    warnings.append("source_unavailable")
    return {"interface": "unknown", "gateway": None}


def _interfaces(probe: object, warnings: list[str]) -> list[dict[str, object]]:
    records = _run_json(probe, IP_ADDRESS_COMMAND, warnings)
    if not isinstance(records, list):
        warnings.append("source_unavailable")
        return []
    result: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, Mapping) or not record.get("ifname"):
            continue
        addresses: list[str] = []
        for address in record.get("addr_info", []):
            if isinstance(address, Mapping) and address.get("local"):
                addresses.append(bounded_text(address.get("local"), fallback="", limit=64))
        result.append(
            {
                "name": bounded_text(record.get("ifname"), fallback="unknown", limit=64),
                "addresses": list(dict.fromkeys(addresses))[:16],
            }
        )
    return result[:64]
