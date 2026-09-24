"""Applied policy cache is bounded, validated and atomically replaced."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1
from pc_agent.policy.cache import AppliedPolicyCache, PolicyCacheError
from tests.contracts.test_endpoint_policy_v1 import _policy


def _delivery() -> EndpointPolicyDeliveryV1:
    policy = EndpointPolicyV1.model_validate(_policy())
    return EndpointPolicyDeliveryV1(
        schema_version="endpoint_policy_delivery_v1", policy_version_id=uuid4(),
        policy=policy, policy_digest=policy_digest(policy), issued_at=datetime.now(UTC),
    )


def test_cache_round_trips_only_validated_policy(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    delivery = _delivery()
    cache.store(delivery, applied_at=datetime.now(UTC))
    stored = cache.load()
    assert stored is not None
    assert stored.policy_version_id == delivery.policy_version_id
    assert stored.policy_digest == delivery.policy_digest
    assert stored.policy.browser_sensor.deployment_mode == "agent_managed"
    assert "device-credential" not in cache.path.read_text(encoding="utf-8")


def test_bad_digest_and_extra_fields_are_not_loaded(tmp_path) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    cache.store(_delivery(), applied_at=datetime.now(UTC))
    payload = cache.path.read_text(encoding="utf-8")
    cache.path.write_text(payload.replace('"policy_digest":"', '"policy_digest":"0'), encoding="utf-8")
    with pytest.raises(PolicyCacheError):
        cache.load()


def test_failed_replace_preserves_last_good_cache(tmp_path, monkeypatch) -> None:
    cache = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    first = _delivery()
    cache.store(first, applied_at=datetime.now(UTC))
    original = cache.path.read_bytes()

    def reject_replace(_source, _target):
        raise OSError("synthetic failed replacement")

    monkeypatch.setattr(os, "replace", reject_replace)
    with pytest.raises(PolicyCacheError):
        cache.store(_delivery(), applied_at=datetime.now(UTC))
    assert cache.path.read_bytes() == original
    assert list(tmp_path.glob("*.tmp")) == []


def test_cache_rejects_file_that_fails_acl_inspection(tmp_path) -> None:
    writer = AppliedPolicyCache(tmp_path, protector=lambda _: None, inspector=lambda _: None)
    writer.store(_delivery(), applied_at=datetime.now(UTC))

    def reject_acl(_path) -> None:
        raise RuntimeError("untrusted file ACL")

    reader = AppliedPolicyCache(tmp_path, inspector=reject_acl)
    with pytest.raises(PolicyCacheError, match="validation"):
        reader.load()
