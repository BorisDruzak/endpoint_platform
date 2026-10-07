"""Source freeze input, deliberately unbound in the implementation commit.

Each later reviewed immutable83/86/87 freeze sets this literal and the canonical
pc_agent.version literal to the SAME reserved fixture version in its own commit.
Neither an environment variable, build parameter nor runtime argv selects it.
"""
FIXTURE_VERSION = None


def require_binding(compiled_version: str) -> str:
    if FIXTURE_VERSION not in {"3.2.83", "3.2.86", "3.2.87"} or compiled_version != FIXTURE_VERSION:
        raise ValueError("fixture version must be independently frozen")
    return FIXTURE_VERSION
