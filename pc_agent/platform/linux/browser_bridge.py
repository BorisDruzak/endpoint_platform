"""Linux transport for the common credential-free Chromium Native Messaging host."""
from __future__ import annotations

from collections.abc import Sequence
from typing import BinaryIO

from pc_agent.browser_bridge import (
    BrowserBridgeInvocationError, ForwardMessage, validate_native_invocation,
    run_native_bridge as _run_native_bridge,
)
from pc_agent.browser_protocol import BrowserBridgeAckV1
from pc_agent.local_sensor_protocol import LocalBrowserEnvelopeV1, serialize_local_sensor_payload
from .local_ipc import exchange


def forward_to_agent(envelope: LocalBrowserEnvelopeV1) -> BrowserBridgeAckV1:
    return BrowserBridgeAckV1.model_validate_json(exchange(serialize_local_sensor_payload(envelope)))


def run_native_bridge(*, stdin: BinaryIO, stdout: BinaryIO,
                      arguments: Sequence[str], expected_extension_id: str,
                      forward: ForwardMessage = forward_to_agent) -> None:
    _run_native_bridge(stdin=stdin, stdout=stdout, arguments=arguments,
                       expected_extension_id=expected_extension_id, forward=forward)
