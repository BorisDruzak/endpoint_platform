"""Stable SHA-256 identity for canonical Device Context baselines."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def semantic_hash(canonical: Mapping[str, object]) -> str:
    """Hash deterministic JSON, never a source-specific Python representation."""
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = ["semantic_hash"]
