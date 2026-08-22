"""Fixed Linux/systemd startup boundary for first-boot Endpoint enrollment."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml

from pc_agent.core.device_fingerprint import collect_device_fingerprint
from pc_agent.enrollment_bootstrap import (
    BootstrapConfig,
    EnrollmentOutcome,
    HANDOFF_REQUEST_PATH,
    PERMANENT_CREDENTIAL_PATH,
    SYSTEMD_CLAIM_CREDENTIAL_NAME,
    _derive_hardware_fingerprint,
    bootstrap_enrollment,
)


PRODUCTION_ENDPOINT_ORIGIN = "https://endpoint.sosnadmin.local"
STAGING_ENDPOINT_ORIGIN = "https://endpoint-staging.sosnadmin.local"
SYSTEMD_CONFIG_CREDENTIAL_NAME = "endpoint-agent-config"
SYSTEMD_CA_CREDENTIAL_NAME = "endpoint-agent-ca"
_CONFIGURED_CA_PATH = "/etc/endpoint-agent/ca.crt"
_PERMANENT_CREDENTIAL_CONFIG_PATH = "/var/lib/endpoint-agent/device-credential"
_SYSTEMD_CREDENTIALS_DIRECTORY = "/run/credentials/endpoint-agent.service"


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a mapping")
    return value


def _text(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def configured_endpoint_origin(
    environment: Mapping[str, str] | None = None,
) -> str:
    """Return the sole allowed origin for the explicitly selected deployment."""
    values = os.environ if environment is None else environment
    deployment = values.get("ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT", "production").strip().lower()
    if deployment == "production":
        return PRODUCTION_ENDPOINT_ORIGIN
    if deployment != "staging":
        raise ValueError("ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT must be production or staging")
    if values.get("CANARY_ENVIRONMENT", "").strip().lower() != "staging":
        raise ValueError("staging agent requires CANARY_ENVIRONMENT=staging")
    if values.get("CANARY_APPROVED", "").strip().lower() != "true":
        raise ValueError("staging agent requires CANARY_APPROVED=true")
    return STAGING_ENDPOINT_ORIGIN


def _credentials_directory(
    *, config_path: Path, ca_file: Path, claim_file: Path
) -> Path:
    directory = config_path.parent
    if ca_file.parent != directory or claim_file.parent != directory:
        raise ValueError("runtime inputs must share same systemd credentials directory")
    if (
        config_path.name != SYSTEMD_CONFIG_CREDENTIAL_NAME
        or ca_file.name != SYSTEMD_CA_CREDENTIAL_NAME
        or claim_file.name != SYSTEMD_CLAIM_CREDENTIAL_NAME
    ):
        raise ValueError("runtime input names must be the fixed systemd credentials")
    return directory


def load_linux_bootstrap_config(
    *, config_path: Path, ca_file: Path, claim_file: Path, uid: int, gid: int
) -> BootstrapConfig:
    """Load only the installed non-secret configuration and fixed credentials."""
    credentials_dir = _credentials_directory(
        config_path=config_path, ca_file=ca_file, claim_file=claim_file
    )
    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError("invalid endpoint-agent runtime configuration") from error
    root = _mapping(payload, name="configuration")
    gateway = _mapping(root.get("gateway"), name="gateway")
    provisioning = _mapping(root.get("provisioning"), name="provisioning")
    endpoint_url = _text(gateway.get("endpoint"), name="gateway.endpoint")
    if endpoint_url != configured_endpoint_origin():
        raise ValueError("gateway.endpoint must be the configured HTTPS origin")
    if gateway.get("ca_file") != _CONFIGURED_CA_PATH:
        raise ValueError("gateway.ca_file must be the fixed installed CA path")
    if provisioning.get("systemd_claim_credential_name") != SYSTEMD_CLAIM_CREDENTIAL_NAME:
        raise ValueError("unknown systemd enrollment claim credential")
    if provisioning.get("permanent_credential_file") != _PERMANENT_CREDENTIAL_CONFIG_PATH:
        raise ValueError("permanent credential path must be fixed")
    installation_id = _text(
        provisioning.get("installation_id"), name="provisioning.installation_id"
    )
    config = BootstrapConfig(
        endpoint_url=endpoint_url,
        ca_file=ca_file,
        installation_id=installation_id,
        credential_path=PERMANENT_CREDENTIAL_PATH,
        handoff_request_path=HANDOFF_REQUEST_PATH,
        service_uid=uid,
        service_gid=gid,
        claim_credential_name=SYSTEMD_CLAIM_CREDENTIAL_NAME,
    )
    config.validate()
    if not credentials_dir.is_dir():
        raise ValueError("systemd credentials directory is missing")
    return config


def systemd_runtime_paths(environment: Mapping[str, str] | None = None) -> tuple[Path, Path, Path] | None:
    """Return all-or-nothing systemd credential paths without accepting alternatives."""
    values = os.environ if environment is None else environment
    raw = (
        values.get("ENDPOINT_AGENT_CONFIG", "").strip(),
        values.get("ENDPOINT_AGENT_CA_FILE", "").strip(),
        values.get("ENDPOINT_AGENT_PROVISIONING_HANDOFF_FILE", "").strip(),
    )
    if not any(raw):
        return None
    if not all(raw):
        raise ValueError("all Endpoint agent systemd credentials are required")
    expected = (
        f"{_SYSTEMD_CREDENTIALS_DIRECTORY}/{SYSTEMD_CONFIG_CREDENTIAL_NAME}",
        f"{_SYSTEMD_CREDENTIALS_DIRECTORY}/{SYSTEMD_CA_CREDENTIAL_NAME}",
        f"{_SYSTEMD_CREDENTIALS_DIRECTORY}/{SYSTEMD_CLAIM_CREDENTIAL_NAME}",
    )
    if raw != expected:
        raise ValueError("Endpoint agent credentials must use the fixed systemd paths")
    return tuple(Path(value) for value in raw)  # type: ignore[return-value]


def derive_linux_hardware_fingerprint(
    probe: Callable[[], object] = collect_device_fingerprint,
) -> str:
    """Derive the claim binding with the exact existing bootstrap algorithm."""
    return _derive_hardware_fingerprint(probe)


async def run_linux_enrollment_gate(
    *,
    config_path: Path,
    ca_file: Path,
    claim_file: Path,
    probe: Callable[[], object] = collect_device_fingerprint,
    uid: int | None = None,
    gid: int | None = None,
) -> EnrollmentOutcome:
    """Run the first-boot claim exchange before normal agent work begins."""
    resolved_uid = os.getuid() if uid is None else uid
    resolved_gid = os.getgid() if gid is None else gid
    config = load_linux_bootstrap_config(
        config_path=config_path,
        ca_file=ca_file,
        claim_file=claim_file,
        uid=resolved_uid,
        gid=resolved_gid,
    )
    return await bootstrap_enrollment(claim_file.parent, config, probe)


__all__ = [
    "PRODUCTION_ENDPOINT_ORIGIN",
    "STAGING_ENDPOINT_ORIGIN",
    "configured_endpoint_origin",
    "derive_linux_hardware_fingerprint",
    "load_linux_bootstrap_config",
    "run_linux_enrollment_gate",
    "systemd_runtime_paths",
]
