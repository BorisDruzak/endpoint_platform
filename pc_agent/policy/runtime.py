"""Apply validated Policy only when its continuous sensors are actually ready."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from threading import Lock

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.gateway_ws import EndpointPolicyAckV1, EndpointPolicyDeliveryV1

from .cache import AppliedPolicyCache, PolicyCacheError


logger = logging.getLogger(__name__)
PolicyApplicator = Callable[[EndpointPolicyV1], Awaitable[None]]


class PolicyApplicationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def _apply_no_sensors(policy: EndpointPolicyV1) -> None:
    if (
        policy.activity.enabled
        or policy.activity.foreground_application
        or policy.activity.browser_context
        or policy.browser_sensor.required
        or policy.browser_sensor.deployment_mode == "agent_managed"
        or any(
            mode == "audit" for mode in (
                policy.dlp.usb_device_events,
                policy.dlp.print_events,
                policy.dlp.browser_upload_events,
                policy.dlp.browser_paste_events,
            )
        )
    ):
        raise PolicyApplicationError("SENSOR_NOT_READY")


class PolicyRuntime:
    def __init__(
        self,
        cache: AppliedPolicyCache,
        *,
        apply_sensors: PolicyApplicator = _apply_no_sensors,
    ) -> None:
        self._cache = cache
        self._apply_sensors = apply_sensors
        self._policy_lock = Lock()
        self._current_policy: EndpointPolicyV1 | None = None

    @property
    def current_policy(self) -> EndpointPolicyV1 | None:
        """Expose only a successfully applied policy to the local sensor thread."""
        with self._policy_lock:
            return self._current_policy

    def _set_current_policy(self, policy: EndpointPolicyV1) -> None:
        with self._policy_lock:
            self._current_policy = policy

    async def restore_offline(self) -> bool:
        """Reactivate last applied policy before network connection when possible."""
        try:
            stored = self._cache.load()
            if stored is None:
                return False
            await self._apply_sensors(stored.policy)
            self._set_current_policy(stored.policy)
            return True
        except (PolicyCacheError, PolicyApplicationError):
            logger.warning("Endpoint Policy cache could not be restored")
            return False
        except Exception:
            logger.exception("Endpoint Policy offline restore failed")
            return False

    async def apply_delivery(self, delivery: EndpointPolicyDeliveryV1) -> EndpointPolicyAckV1:
        received_at = datetime.now(UTC)
        error_code: str | None = None
        applied_at: datetime | None = None
        try:
            await self._apply_sensors(delivery.policy)
            applied_at = datetime.now(UTC)
            self._cache.store(delivery, applied_at=applied_at)
            self._set_current_policy(delivery.policy)
        except PolicyApplicationError as error:
            error_code = error.code
        except PolicyCacheError:
            error_code = "CACHE_WRITE_FAILED"
        except Exception:
            logger.exception("Endpoint Policy sensor application failed")
            error_code = "SENSOR_APPLY_FAILED"
        return EndpointPolicyAckV1(
            schema_version="endpoint_policy_ack_v1",
            policy_id=delivery.policy.policy_id,
            policy_version=delivery.policy.policy_version,
            policy_digest=delivery.policy_digest,
            received_at=received_at,
            applied_at=applied_at if error_code is None else None,
            status="APPLIED" if error_code is None else "ERROR",
            error_code=error_code,
        )
