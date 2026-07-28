"""Validated, fail-closed configuration for the Endpoint Platform server."""

from __future__ import annotations

import ipaddress
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, TypeAlias
from urllib.parse import urlsplit


Network: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network

_PRODUCTION_PUBLIC_HOST = "endpoint.sosnadmin.local"
_SECRET_MODE_MASK = stat.S_IRGRP | stat.S_IROTH


def _require_setting(name: str, environment: Mapping[str, str]) -> str:
    value = environment.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _validate_secret_metadata(path: Path, mode: int) -> None:
    if stat.S_ISLNK(mode):
        raise ValueError(f"secret file {path} must not be a symlink")
    if not stat.S_ISREG(mode):
        raise ValueError(f"secret file {path} must be a regular file")
    if os.name != "nt" and mode & _SECRET_MODE_MASK:
        raise ValueError(f"secret file {path} must not be group or world readable")


def load_secret_file(path: Path) -> bytes:
    """Read non-empty credential material from one private, regular file."""
    try:
        _validate_secret_metadata(path, path.lstat().st_mode)
    except OSError as error:
        raise ValueError(f"secret file {path} is missing or inaccessible") from error

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"secret file {path} is missing or inaccessible") from error

    with os.fdopen(descriptor, "rb") as secret_file:
        try:
            _validate_secret_metadata(path, os.fstat(secret_file.fileno()).st_mode)
        except OSError as error:
            raise ValueError(f"secret file {path} is missing or inaccessible") from error
        secret = secret_file.read()

    if not secret:
        raise ValueError(f"secret file {path} must not be empty")
    return secret


def _parse_public_base_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == _PRODUCTION_PUBLIC_HOST
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid = False

    if not valid:
        raise ValueError(
            "PUBLIC_BASE_URL must be the HTTPS origin for "
            f"{_PRODUCTION_PUBLIC_HOST}"
        )
    return f"https://{_PRODUCTION_PUBLIC_HOST}"


def _parse_cidrs(name: str, value: str) -> tuple[Network, ...]:
    entries = tuple(entry.strip() for entry in value.split(","))
    if not entries or any(not entry for entry in entries):
        raise ValueError(f"{name} must contain one or more CIDRs")
    try:
        return tuple(ipaddress.ip_network(entry, strict=True) for entry in entries)
    except ValueError as error:
        raise ValueError(f"{name} must contain valid CIDRs") from error


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime values loaded once during server startup."""

    database_url: str
    public_base_url: str
    device_token_pepper: bytes
    service_token_pepper: bytes
    session_secret: bytes
    allowed_agent_cidrs: tuple[Network, ...]
    allowed_admin_cidrs: tuple[Network, ...]
    artifact_root: Path

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> Settings:
        values = MappingProxyType(dict(os.environ) if environment is None else dict(environment))
        database_url = _require_setting("DATABASE_URL", values)
        public_base_url = _parse_public_base_url(_require_setting("PUBLIC_BASE_URL", values))
        device_token_pepper = load_secret_file(
            Path(_require_setting("DEVICE_TOKEN_PEPPER_FILE", values))
        )
        service_token_pepper = load_secret_file(
            Path(_require_setting("SERVICE_TOKEN_PEPPER_FILE", values))
        )
        session_secret = load_secret_file(Path(_require_setting("SESSION_SECRET_FILE", values)))
        allowed_agent_cidrs = _parse_cidrs(
            "ALLOWED_AGENT_CIDRS", _require_setting("ALLOWED_AGENT_CIDRS", values)
        )
        allowed_admin_cidrs = _parse_cidrs(
            "ALLOWED_ADMIN_CIDRS", _require_setting("ALLOWED_ADMIN_CIDRS", values)
        )
        artifact_root = Path(_require_setting("ARTIFACT_ROOT", values))

        return cls(
            database_url=database_url,
            public_base_url=public_base_url,
            device_token_pepper=device_token_pepper,
            service_token_pepper=service_token_pepper,
            session_secret=session_secret,
            allowed_agent_cidrs=allowed_agent_cidrs,
            allowed_admin_cidrs=allowed_admin_cidrs,
            artifact_root=artifact_root,
        )
