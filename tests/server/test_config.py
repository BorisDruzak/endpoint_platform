from __future__ import annotations

import os
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from endpoint_server.config import Settings, load_secret_file


def _write_secret(path: Path, value: bytes = b"secret-value") -> Path:
    path.write_bytes(value)
    if os.name != "nt":
        path.chmod(0o600)
    return path


def _environment(tmp_path: Path) -> dict[str, str]:
    return {
        "DATABASE_URL": "postgresql+asyncpg://endpoint:password@db/endpoint",
        "PUBLIC_BASE_URL": "https://endpoint.sosnadmin.local",
        "DEVICE_TOKEN_PEPPER_FILE": str(_write_secret(tmp_path / "device-pepper")),
        "SERVICE_TOKEN_PEPPER_FILE": str(_write_secret(tmp_path / "service-pepper")),
        "SESSION_SECRET_FILE": str(_write_secret(tmp_path / "session-secret")),
        "ALLOWED_AGENT_CIDRS": "10.20.0.0/16, 2001:db8:100::/48",
        "ALLOWED_ADMIN_CIDRS": "192.168.100.0/24",
        "ARTIFACT_ROOT": str(tmp_path / "artifacts"),
    }


def test_from_environment_loads_secret_bytes_and_parses_cidrs(tmp_path: Path) -> None:
    """Removing safe secret loading or CIDR parsing must break startup settings."""
    settings = Settings.from_environment(_environment(tmp_path))

    assert settings.device_token_pepper == b"secret-value"
    assert settings.service_token_pepper == b"secret-value"
    assert settings.session_secret == b"secret-value"
    assert tuple(str(network) for network in settings.allowed_agent_cidrs) == (
        "10.20.0.0/16",
        "2001:db8:100::/48",
    )
    assert tuple(str(network) for network in settings.allowed_admin_cidrs) == (
        "192.168.100.0/24",
    )
    assert settings.trusted_proxy_cidrs == ()
    assert settings.endpoint_operations_api_enabled is False


def test_from_environment_enables_endpoint_operations_only_explicitly(
    tmp_path: Path,
) -> None:
    """A missing flag must stay disabled while one explicit true value opts in."""
    environment = _environment(tmp_path)
    environment["ENDPOINT_OPERATIONS_API_ENABLED"] = "true"

    settings = Settings.from_environment(environment)

    assert settings.endpoint_operations_api_enabled is True


def test_from_environment_loads_network_primitive_flag_and_allowlists(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    environment.update(
        {
            "ENDPOINT_NETWORK_PRIMITIVES_ENABLED": "true",
            "ENDPOINT_NETWORK_PROBE_ALLOWED_CIDRS": "10.20.0.0/16",
            "ENDPOINT_NETWORK_PROBE_ALLOWED_SUFFIXES": ".example.test,.internal.test",
        }
    )

    settings = Settings.from_environment(environment)

    assert settings.endpoint_network_primitives_enabled is True
    assert tuple(str(item) for item in settings.endpoint_network_probe_allowed_cidrs) == (
        "10.20.0.0/16",
    )
    assert settings.endpoint_network_probe_allowed_suffixes == (
        ".example.test",
        ".internal.test",
    )


def test_from_environment_keeps_module_platform_and_execution_default_closed(
    tmp_path: Path,
) -> None:
    default_settings = Settings.from_environment(_environment(tmp_path))
    environment = _environment(tmp_path)
    environment.update(
        {
            "ENDPOINT_MODULE_PLATFORM_ENABLED": "true",
            "ENDPOINT_MODULE_EXECUTION_ENABLED": "true",
        }
    )

    enabled_settings = Settings.from_environment(environment)

    assert default_settings.endpoint_module_platform_enabled is False
    assert default_settings.endpoint_module_execution_enabled is False
    assert enabled_settings.endpoint_module_platform_enabled is True
    assert enabled_settings.endpoint_module_execution_enabled is True


def test_from_environment_rejects_module_execution_without_platform_flag(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    environment["ENDPOINT_MODULE_EXECUTION_ENABLED"] = "true"

    with pytest.raises(ValueError, match="ENDPOINT_MODULE_PLATFORM_ENABLED"):
        Settings.from_environment(environment)


def test_from_environment_rejects_ambiguous_endpoint_operations_flag(
    tmp_path: Path,
) -> None:
    """Typos must not accidentally expose or silently disable the service API."""
    environment = _environment(tmp_path)
    environment["ENDPOINT_OPERATIONS_API_ENABLED"] = "sometimes"

    with pytest.raises(ValueError, match="ENDPOINT_OPERATIONS_API_ENABLED"):
        Settings.from_environment(environment)


def test_from_environment_parses_optional_trusted_proxy_cidrs(
    tmp_path: Path,
) -> None:
    """Configured reverse proxies must be explicit networks, never implicit trust."""
    environment = _environment(tmp_path)
    environment["TRUSTED_PROXY_CIDRS"] = "127.0.0.1/32, 2001:db8:200::/48"

    settings = Settings.from_environment(environment)

    assert tuple(str(network) for network in settings.trusted_proxy_cidrs) == (
        "127.0.0.1/32",
        "2001:db8:200::/48",
    )


def test_from_environment_rejects_malformed_trusted_proxy_cidr(
    tmp_path: Path,
) -> None:
    """Malformed proxy trust must fail startup instead of trusting an unknown peer."""
    environment = _environment(tmp_path)
    environment["TRUSTED_PROXY_CIDRS"] = "not-a-proxy-network"

    with pytest.raises(ValueError, match="TRUSTED_PROXY_CIDRS"):
        Settings.from_environment(environment)


def test_settings_are_immutable_after_startup(tmp_path: Path) -> None:
    """Mutating loaded settings could silently weaken a running service's policy."""
    settings = Settings.from_environment(_environment(tmp_path))

    with pytest.raises(FrozenInstanceError):
        settings.database_url = "postgresql+asyncpg://other"


@pytest.mark.parametrize(
    "public_base_url",
    [
        "http://endpoint.sosnadmin.local",
        "https://gateway.sosnadmin.local",
        "https://endpoint.sosnadmin.local/api",
    ],
)
def test_from_environment_rejects_non_production_https_public_url(
    tmp_path: Path, public_base_url: str
) -> None:
    """Accepting a non-canonical public URL could expose unsafe callback URLs."""
    environment = _environment(tmp_path)
    environment["PUBLIC_BASE_URL"] = public_base_url

    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        Settings.from_environment(environment)


def test_from_environment_accepts_exact_staging_origin_only_with_canary_markers(
    tmp_path: Path,
) -> None:
    environment = _environment(tmp_path)
    environment.update(
        {
            "PUBLIC_BASE_URL": "https://endpoint-staging.sosnadmin.local",
            "ENDPOINT_DEPLOYMENT_ENVIRONMENT": "staging",
            "CANARY_ENVIRONMENT": "staging",
            "CANARY_APPROVED": "true",
        }
    )

    settings = Settings.from_environment(environment)

    assert settings.public_base_url == "https://endpoint-staging.sosnadmin.local"


@pytest.mark.parametrize(
    "marker_overrides",
    [
        {},
        {"CANARY_APPROVED": "false"},
        {"CANARY_ENVIRONMENT": "production", "CANARY_APPROVED": "true"},
    ],
)
def test_from_environment_rejects_staging_origin_without_exact_canary_markers(
    tmp_path: Path, marker_overrides: dict[str, str]
) -> None:
    environment = _environment(tmp_path)
    environment.update(
        {
            "PUBLIC_BASE_URL": "https://endpoint-staging.sosnadmin.local",
            "ENDPOINT_DEPLOYMENT_ENVIRONMENT": "staging",
        }
    )
    environment.update(marker_overrides)

    with pytest.raises(ValueError, match="staging"):
        Settings.from_environment(environment)


@pytest.mark.parametrize(
    "variable",
    [
        "DATABASE_URL",
        "PUBLIC_BASE_URL",
        "DEVICE_TOKEN_PEPPER_FILE",
        "SERVICE_TOKEN_PEPPER_FILE",
        "SESSION_SECRET_FILE",
        "ALLOWED_AGENT_CIDRS",
        "ALLOWED_ADMIN_CIDRS",
        "ARTIFACT_ROOT",
    ],
)
def test_from_environment_requires_each_setting(tmp_path: Path, variable: str) -> None:
    """Removing a required setting must fail closed instead of applying a default."""
    environment = _environment(tmp_path)
    environment[variable] = ""

    with pytest.raises(ValueError, match=variable):
        Settings.from_environment(environment)


def test_from_environment_rejects_malformed_cidr(tmp_path: Path) -> None:
    """Passing an unparsed network string to access control must fail startup."""
    environment = _environment(tmp_path)
    environment["ALLOWED_AGENT_CIDRS"] = "not-a-network"

    with pytest.raises(ValueError, match="ALLOWED_AGENT_CIDRS"):
        Settings.from_environment(environment)


def test_load_secret_file_rejects_missing_and_empty_files(tmp_path: Path) -> None:
    """Treating absent or empty secret material as valid would weaken authentication."""
    missing_secret = tmp_path / "missing-secret"
    empty_secret = _write_secret(tmp_path / "empty-secret", b"")

    for path in (missing_secret, empty_secret):
        with pytest.raises(ValueError, match="secret file"):
            load_secret_file(path)


def test_load_secret_file_rejects_directory(tmp_path: Path) -> None:
    """Opening a directory as credential material must fail before it is read."""
    with pytest.raises(ValueError, match="regular file"):
        load_secret_file(tmp_path)


def test_load_secret_file_rejects_symlink(tmp_path: Path) -> None:
    """Following a symlink could substitute secret material after validation."""
    target = _write_secret(tmp_path / "target")
    symlink = tmp_path / "linked-secret"
    try:
        symlink.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable on this host: {error}")

    with pytest.raises(ValueError, match="symlink"):
        load_secret_file(symlink)


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows stat modes do not represent POSIX group/world readability",
)
def test_load_secret_file_rejects_group_or_world_readable_file(tmp_path: Path) -> None:
    """Accepting a mode 0644 secret would let other local users read credential material."""
    secret = _write_secret(tmp_path / "readable-secret")
    secret.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    with pytest.raises(ValueError, match="group or world readable"):
        load_secret_file(secret)
