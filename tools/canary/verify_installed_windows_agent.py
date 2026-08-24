"""Fail-closed validation of redacted Windows EndpointAgent preflight facts."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from tools.canary.evidence_models import (
    CanaryEvidenceError,
    validate_evidence_payload,
    write_secure_json,
)


class WindowsPreflightError(ValueError):
    """A Windows installed-agent canary invariant was not proven."""


_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "agent",
        "services",
        "runtime",
        "msi",
        "acl",
        "safe_status",
        "network",
        "completion_proof",
    }
)


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsPreflightError(f"{name} schema is invalid")
    return value


def validate_preflight(
    projection: Mapping[str, object], manifest: Mapping[str, object]
) -> dict[str, object]:
    """Validate only a bounded, redacted Windows preflight projection."""
    if set(projection) != _TOP_LEVEL_KEYS:
        raise WindowsPreflightError("projection schema is invalid")
    if projection.get("schema_version") != "windows_agent_preflight_v1":
        raise WindowsPreflightError("projection schema is invalid")
    agent = _mapping(projection["agent"], name="agent")
    manifest_agent = _mapping(manifest.get("agent"), name="manifest agent")
    if agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("agent platform is invalid")
    if manifest_agent.get("platform") != "windows_amd64":
        raise WindowsPreflightError("manifest platform is invalid")
    try:
        validate_evidence_payload(projection, allowed_keys=_TOP_LEVEL_KEYS)
    except CanaryEvidenceError as error:
        raise WindowsPreflightError("projection contains forbidden evidence") from error
    return {"status": "READY", "platform": "windows_amd64"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projection", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        projection = json.loads(args.projection.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = validate_preflight(
            _mapping(projection, name="projection"), _mapping(manifest, name="manifest")
        )
        write_secure_json(args.output, result, allowed_keys=frozenset(result))
    except (OSError, json.JSONDecodeError, WindowsPreflightError) as error:
        print(f"windows preflight failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
