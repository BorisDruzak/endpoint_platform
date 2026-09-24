"""Protected, atomic cache of the last successfully applied Endpoint Policy."""

from __future__ import annotations

import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Callable, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, model_validator

from endpoint_contracts.base import ContractModelV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1, policy_digest
from endpoint_contracts.gateway_ws import EndpointPolicyDeliveryV1, PolicyDigestV1


POLICY_CACHE_FILENAME = "applied-endpoint-policy-v1.json"
MAX_POLICY_CACHE_BYTES = 64 * 1024
_REPARSE_ATTRIBUTE = 0x400


class PolicyCacheError(RuntimeError):
    """Policy cache could not be trusted or durably updated."""


class AppliedPolicyCacheV1(ContractModelV1):
    schema_version: Literal["applied_endpoint_policy_cache_v1"]
    policy_version_id: UUID
    policy: EndpointPolicyV1
    policy_digest: PolicyDigestV1
    applied_at: AwareDatetime

    @model_validator(mode="after")
    def validate_digest(self) -> "AppliedPolicyCacheV1":
        if self.policy_digest != policy_digest(self.policy):
            raise ValueError("cached policy digest does not match document")
        return self


def _require_safe_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise PolicyCacheError("protected Agent data directory is unavailable") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or getattr(details, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    ):
        raise PolicyCacheError("protected Agent data directory is unsafe")


def _default_protector(path: Path) -> None:
    if os.name == "nt":
        from pc_agent.platform.windows.acl import PyWin32AclAdapter

        PyWin32AclAdapter().protect_machine_data_file(path)
    else:
        path.chmod(0o600)


def _default_inspector(path: Path) -> None:
    if os.name == "nt":
        from pc_agent.platform.windows.acl import PyWin32AclAdapter

        PyWin32AclAdapter().assert_protected_file(path)
    else:
        details = path.stat()
        if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise PolicyCacheError("cached policy is not private")


class AppliedPolicyCache:
    def __init__(
        self,
        data_root: Path,
        *,
        protector: Callable[[Path], None] | None = None,
        inspector: Callable[[Path], None] | None = None,
    ) -> None:
        self._data_root = Path(data_root)
        self._protector = protector or _default_protector
        self._inspector = inspector or _default_inspector
        self.path = self._data_root / POLICY_CACHE_FILENAME

    def load(self) -> AppliedPolicyCacheV1 | None:
        _require_safe_directory(self._data_root)
        try:
            details = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PolicyCacheError("cached policy is inaccessible") from error
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or getattr(details, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
            or details.st_size > MAX_POLICY_CACHE_BYTES
        ):
            raise PolicyCacheError("cached policy file is unsafe")
        try:
            self._inspector(self.path)
            with self.path.open("rb") as stream:
                encoded = stream.read(MAX_POLICY_CACHE_BYTES + 1)
            if len(encoded) > MAX_POLICY_CACHE_BYTES:
                raise PolicyCacheError("cached policy exceeds size limit")
            return AppliedPolicyCacheV1.model_validate_json(encoded)
        except (OSError, ValueError, RuntimeError) as error:
            raise PolicyCacheError("cached policy failed validation") from error

    def store(
        self,
        delivery: EndpointPolicyDeliveryV1,
        *,
        applied_at: datetime,
    ) -> AppliedPolicyCacheV1:
        _require_safe_directory(self._data_root)
        record = AppliedPolicyCacheV1(
            schema_version="applied_endpoint_policy_cache_v1",
            policy_version_id=delivery.policy_version_id,
            policy=delivery.policy,
            policy_digest=delivery.policy_digest,
            applied_at=applied_at,
        )
        encoded = record.model_dump_json().encode("utf-8")
        if len(encoded) > MAX_POLICY_CACHE_BYTES:
            raise PolicyCacheError("policy exceeds cache size limit")
        temporary = self._data_root / f".{POLICY_CACHE_FILENAME}.{uuid4().hex}.tmp"
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self._protector(temporary)
            os.replace(temporary, self.path)
            if os.name != "nt":
                directory_fd = os.open(self._data_root, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except Exception as error:
            raise PolicyCacheError("could not atomically store applied policy") from error
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass
        return record
