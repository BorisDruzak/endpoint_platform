"""Apply the available Windows policy-owned sensor integration."""

from __future__ import annotations

import asyncio
import logging

from endpoint_contracts.endpoint_policy import EndpointPolicyV1

from pc_agent.platform.windows.browser_policy_helper import send_policy_request

from .runtime import PolicyApplicationError


_LOG = logging.getLogger(__name__)
_HELPER_STARTUP_RETRY_DELAYS = (0.25, 0.5, 1.0, 2.0, 2.0, 2.0)


async def _request_browser_policy_with_startup_retry(
    operation: str, family: str,
) -> str:
    """Wait briefly for the fixed helper pipe when SCM starts it after Agent."""
    for delay in _HELPER_STARTUP_RETRY_DELAYS:
        try:
            return await asyncio.to_thread(send_policy_request, operation, family)
        except Exception as error:
            if getattr(error, "winerror", None) not in (2, 231):
                raise
            await asyncio.sleep(delay)
    return await asyncio.to_thread(send_policy_request, operation, family)


async def apply_windows_policy_sensors(
    policy: EndpointPolicyV1, *, activity_available: bool = False,
    browser_audit_available: bool = False, usb_available: bool = False,
    print_available: bool = False,
) -> None:
    """Apply browser ownership only after requested local sensors are ready."""
    if (
        (
            (
                policy.activity.enabled
                or policy.activity.foreground_application
                or policy.activity.browser_context
            )
            and not activity_available
        )
        or (policy.dlp.usb_device_events == "audit" and not usb_available)
        or (policy.dlp.print_events == "audit" and not print_available)
        or (
            (
                policy.dlp.browser_upload_events == "audit"
                or policy.dlp.browser_paste_events == "audit"
            )
            and not browser_audit_available
        )
    ):
        raise PolicyApplicationError("SENSOR_NOT_READY")

    operation = (
        "apply"
        if policy.browser_sensor.deployment_mode == "agent_managed"
        else "relinquish"
    )
    expected = "APPLIED" if operation == "apply" else "EXTERNALLY_MANAGED"
    for family in ("chrome", "yandex"):
        try:
            status = await _request_browser_policy_with_startup_retry(operation, family)
        except Exception as error:
            _LOG.warning("Browser policy helper request failed for %s", family)
            raise PolicyApplicationError("BROWSER_POLICY_HELPER_UNAVAILABLE") from error
        if status == "POLICY_CONFLICT":
            raise PolicyApplicationError("POLICY_CONFLICT")
        if status != expected:
            raise PolicyApplicationError("BROWSER_POLICY_HELPER_FAILED")
