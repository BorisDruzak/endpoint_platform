"""Apply the available Windows policy-owned sensor integration."""

from __future__ import annotations

import asyncio
import logging

from endpoint_contracts.endpoint_policy import EndpointPolicyV1

from pc_agent.platform.windows.browser_policy_helper import send_policy_request

from .runtime import PolicyApplicationError


_LOG = logging.getLogger(__name__)


async def apply_windows_policy_sensors(policy: EndpointPolicyV1) -> None:
    """Apply browser install ownership only after unsupported sensors are rejected."""
    if (
        policy.activity.enabled
        or policy.activity.foreground_application
        or policy.activity.browser_context
        or any(
            mode == "audit"
            for mode in (
                policy.dlp.usb_device_events,
                policy.dlp.print_events,
                policy.dlp.browser_upload_events,
                policy.dlp.browser_paste_events,
            )
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
            status = await asyncio.to_thread(send_policy_request, operation, family)
        except Exception as error:
            _LOG.warning("Browser policy helper request failed for %s", family)
            raise PolicyApplicationError("BROWSER_POLICY_HELPER_UNAVAILABLE") from error
        if status == "POLICY_CONFLICT":
            raise PolicyApplicationError("POLICY_CONFLICT")
        if status != expected:
            raise PolicyApplicationError("BROWSER_POLICY_HELPER_FAILED")
