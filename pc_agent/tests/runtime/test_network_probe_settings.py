"""Runtime-owned policy configuration for typed network primitives."""

from pathlib import Path

import pytest

from pc_agent.runtime.application import RuntimeApplication, RuntimeSettings


def _settings(tmp_path: Path, **overrides: object) -> RuntimeSettings:
    ca_file = tmp_path / "endpoint-ca.crt"
    ca_file.write_text("test CA", encoding="ascii")
    values: dict[str, object] = {
        "data_root": tmp_path / "data",
        "install_root": tmp_path / "install",
        "ca_file": ca_file,
        "endpoint_origin": "https://endpoint.sosnadmin.local",
        "transport_mode": "gateway_wss",
    }
    values.update(overrides)
    return RuntimeSettings(**values)


def test_runtime_settings_builds_network_probe_policy_from_explicit_allowlists(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        network_probe_allowed_cidrs=("10.20.0.0/16",),
        network_probe_allowed_suffixes=(".example.test",),
    )

    settings.validate()
    policy = settings.network_probe_policy()
    policy.require_allowed("10.20.1.10")
    policy.require_allowed("api.example.test")
    with pytest.raises(ValueError, match="network_target_disallowed"):
        policy.require_allowed("api.invalid.test")


def test_runtime_settings_rejects_invalid_network_probe_allowlist_before_start(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, network_probe_allowed_cidrs=("10.20.1.9/16",))

    with pytest.raises(ValueError, match="allowed CIDR"):
        settings.validate()


def test_default_runtime_executor_uses_settings_network_probe_policy(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        network_probe_allowed_suffixes=(".example.test",),
    )

    executor = RuntimeApplication(settings).dependencies.create_executor()

    executor._network_probe_policy.require_allowed("api.example.test")
    with pytest.raises(ValueError, match="network_target_disallowed"):
        executor._network_probe_policy.require_allowed("api.invalid.test")
