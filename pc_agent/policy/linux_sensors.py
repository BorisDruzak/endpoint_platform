"""Apply Linux policy only when its requested local adapters are available."""
from __future__ import annotations

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from .runtime import PolicyApplicationError


async def apply_linux_policy_sensors(
    policy: EndpointPolicyV1, *, activity_available: bool = False,
    browser_audit_available: bool = False, usb_available: bool = False,
    print_available: bool = False,
) -> None:
    if (
        ((policy.activity.enabled or policy.activity.foreground_application or policy.activity.browser_context)
         and not activity_available)
        or (policy.dlp.usb_device_events == 'audit' and not usb_available)
        or (policy.dlp.print_events == 'audit' and not print_available)
        or ((policy.dlp.browser_upload_events == 'audit' or policy.dlp.browser_paste_events == 'audit')
            and not browser_audit_available)
        or policy.browser_sensor.deployment_mode == 'agent_managed'
        or (policy.browser_sensor.required and not browser_audit_available)
    ):
        raise PolicyApplicationError('SENSOR_NOT_READY')
