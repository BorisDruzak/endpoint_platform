"""Source freeze input, deliberately unbound in the implementation commit.

Each later immutable83/86/87 or equivalent direct-B100/60000 freeze sets this literal and the canonical
pc_agent.version literal to the SAME reserved fixture version in its own commit.
Neither an environment variable, build parameter nor runtime argv selects it.
"""
FIXTURE_VERSION = None


def require_binding(compiled_version: str) -> str:
    if FIXTURE_VERSION not in {"3.2.83", "3.2.86", "3.2.87", "3.2.100", "3.2.60000", "3.2.60003", "3.2.60004"} or compiled_version != FIXTURE_VERSION:
        raise ValueError("fixture version must be independently frozen")
    return FIXTURE_VERSION
