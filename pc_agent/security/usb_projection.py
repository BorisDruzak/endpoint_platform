"""Shared policy gate and content-free USB event projection for OS adapters."""
from datetime import UTC, datetime
from uuid import UUID, uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.security_events import UsbConnectedEventV1, UsbDisconnectedEventV1, UsbEventMetadataV1


def project_usb_event(action: str, metadata: UsbEventMetadataV1,
                      policy: EndpointPolicyV1 | None, *, occurred_at: datetime,
                      event_identifier: UUID | None = None):
    if policy is None or policy.dlp.usb_device_events != 'audit' or action not in {'add', 'remove'}:
        return None
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError('USB event time must be timezone-aware')
    event_class, event_type = ((UsbConnectedEventV1, 'USB_DEVICE_CONNECTED') if action == 'add'
                              else (UsbDisconnectedEventV1, 'USB_DEVICE_DISCONNECTED'))
    return event_class(schema_version='security_event_v1', event_identifier=event_identifier or uuid4(),
        severity='INFO', occurred_at=occurred_at.astimezone(UTC), user_login=None,
        policy_id=policy.policy_id, policy_version=policy.policy_version,
        event_type=event_type, channel='USB', safe_metadata=metadata)
