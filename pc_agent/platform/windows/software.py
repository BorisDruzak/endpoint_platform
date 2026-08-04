"""Fixed Windows software baseline; never enumerates installed applications."""

from __future__ import annotations

from pc_agent.context_profiles.stable_keys import bounded_text
from pc_agent.version import AGENT_VERSION


def collect_software() -> list[dict[str, str]]:
    return [{"name": "endpoint-agent", "version": bounded_text(AGENT_VERSION, fallback="unknown", limit=128), "source": "installer"}]


__all__ = ["collect_software"]
