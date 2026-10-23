"""Apply Linux policy only when its requested local adapters are available."""
from __future__ import annotations

import asyncio

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from .runtime import PolicyApplicationError
from pc_agent.platform.linux.browser_policy_client import send_policy_request
from pc_agent.platform.linux.browser_policy import STATE_ROOT


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
        or (policy.browser_sensor.deployment_mode == 'agent_managed' and not browser_audit_available)
        or (policy.browser_sensor.required and not browser_audit_available)
    ):
        raise PolicyApplicationError('SENSOR_NOT_READY')
    # An Activity-only Core without the optional RPM does not need a helper.
    # A previous ownership marker always requires verified relinquish.
    owned = any(path.exists() or path.is_symlink() for path in
                (STATE_ROOT / 'chromium.json', STATE_ROOT / 'chrome.json', STATE_ROOT / 'yandex.json'))
    if not browser_audit_available and not owned:
        return
    operation = 'apply' if policy.browser_sensor.deployment_mode == 'agent_managed' else 'relinquish'
    expected = 'APPLIED' if operation == 'apply' else 'EXTERNALLY_MANAGED'
    for family in ('chrome','yandex'):
        try:
            status = await asyncio.to_thread(send_policy_request, operation, family)
        except Exception as error:
            raise PolicyApplicationError('BROWSER_POLICY_HELPER_UNAVAILABLE') from error
        if status == 'POLICY_CONFLICT':
            raise PolicyApplicationError('POLICY_CONFLICT')
        if status != expected:
            raise PolicyApplicationError('BROWSER_POLICY_HELPER_FAILED')
