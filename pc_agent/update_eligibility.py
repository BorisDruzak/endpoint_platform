"""Pure immutable-release eligibility; safe for the offline updater."""
from __future__ import annotations

import re

_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_ROLLBACK_REASON = re.compile(
    r"^rollback of [0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}; .+"
)


def _is_eligible_recommendation(candidate: str, installed: str, reason: str | None) -> bool:
    candidate_parts = _parse_semver(candidate)
    installed_parts = _parse_semver(installed)
    if candidate_parts is None or installed_parts is None:
        return False
    comparison = _compare_semver_parts(candidate_parts, installed_parts)
    return comparison > 0 or (
        comparison < 0 and isinstance(reason, str) and _ROLLBACK_REASON.fullmatch(reason) is not None
    )


def _compare_semver_parts(
    candidate: tuple[int, int, int, tuple[str, ...] | None],
    installed: tuple[int, int, int, tuple[str, ...] | None],
) -> int:
    if candidate[:3] != installed[:3]:
        return 1 if candidate[:3] > installed[:3] else -1
    return _compare_prerelease(candidate[3], installed[3])


def _parse_semver(value: str) -> tuple[int, int, int, tuple[str, ...] | None] | None:
    match = _SEMVER.fullmatch(value)
    if match is None:
        return None
    prerelease = match.group("pre")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        tuple(prerelease.split(".")) if prerelease else None,
    )


def _compare_prerelease(
    candidate: tuple[str, ...] | None, installed: tuple[str, ...] | None
) -> int:
    if candidate is None:
        return 0 if installed is None else 1
    if installed is None:
        return -1
    for left, right in zip(candidate, installed):
        if left == right:
            continue
        if left.isdigit() and right.isdigit():
            return 1 if int(left) > int(right) else -1
        if left.isdigit():
            return -1
        if right.isdigit():
            return 1
        return 1 if left > right else -1
    if len(candidate) == len(installed):
        return 0
    return 1 if len(candidate) > len(installed) else -1
