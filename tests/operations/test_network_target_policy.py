import pytest

from endpoint_server.policy.network_targets import (
    NetworkTargetPolicyError,
    NetworkTargetPolicyV1,
)


def test_empty_network_probe_allowlists_fail_closed() -> None:
    policy = NetworkTargetPolicyV1.from_values(allowed_cidrs=(), allowed_suffixes=())

    with pytest.raises(NetworkTargetPolicyError, match="network_target_policy_not_configured"):
        policy.require_allowed("8.8.8.8")


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "255.255.255.255"],
)
def test_network_probe_policy_rejects_forbidden_address_classes(target: str) -> None:
    policy = NetworkTargetPolicyV1.from_values(
        allowed_cidrs=("0.0.0.0/0", "::/0"), allowed_suffixes=(".example.test",)
    )

    with pytest.raises(NetworkTargetPolicyError, match="network_target_forbidden_address"):
        policy.require_allowed(target)


def test_network_probe_policy_requires_explicit_cidr_or_suffix_match() -> None:
    policy = NetworkTargetPolicyV1.from_values(
        allowed_cidrs=("10.20.0.0/16",), allowed_suffixes=(".example.test",)
    )

    policy.require_allowed("10.20.1.10")
    policy.require_allowed("api.example.test")
    with pytest.raises(NetworkTargetPolicyError, match="network_target_disallowed"):
        policy.require_allowed("8.8.8.8")
    with pytest.raises(NetworkTargetPolicyError, match="network_target_disallowed"):
        policy.require_allowed("example.test")


def test_network_probe_policy_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="allowed CIDR"):
        NetworkTargetPolicyV1.from_values(
            allowed_cidrs=("not-a-cidr",), allowed_suffixes=(".example.test",)
        )
    with pytest.raises(ValueError, match="allowed suffix"):
        NetworkTargetPolicyV1.from_values(
            allowed_cidrs=("10.20.0.0/16",), allowed_suffixes=("https://example.test",)
        )
