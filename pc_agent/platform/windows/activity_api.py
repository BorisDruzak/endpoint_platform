"""Windows pipe authorization around the shared local sensor projection."""
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_contracts.security_events import SecurityEventV1
from pc_agent.browser_protocol import BrowserBridgeAckV1
from pc_agent.activity_ingress import (
    ActivityIngress as SharedActivityIngress, BrowserHeartbeatFact, _ack,
)
from .local_ipc import (
    PIPE_NAME, ClientIdentity, LocalIpcRejected, authorize_pipe_client,
    read_pipe_frame, resolve_user_login, write_pipe_frame,
)
from .sensor_pipe_listener import LocalSensorPipeListener


class ActivityIngress(SharedActivityIngress):
    def ingest(
        self, payload: bytes, *, identity: ClientIdentity,
        user_login: str | None, policy: EndpointPolicyV1 | None,
        received_at: datetime,
        on_security_event: Callable[[SecurityEventV1], bool] | None = None,
    ) -> tuple[BrowserBridgeAckV1, ActivityObservationV1 | None]:
        return super().ingest(
            payload,
            session_key=(identity.user_sid, identity.logon_sid, identity.token_session_id),
            user_login=user_login, policy=policy, received_at=received_at,
            on_security_event=on_security_event,
        )


def handle_local_sensor_connection(
    pipe_handle: object,
    *,
    ingress: ActivityIngress,
    policy_provider: Callable[[], EndpointPolicyV1 | None],
    on_observation: Callable[[ActivityObservationV1], None],
    on_security_event: Callable[[SecurityEventV1], bool] | None = None,
    received_at: datetime | None = None,
) -> BrowserBridgeAckV1 | None:
    """Read exactly one frame, then impersonate its writer before projection."""
    try:
        payload = read_pipe_frame(pipe_handle)
    except LocalIpcRejected:
        return None  # A broken frame cannot be safely ACKed on the same stream.
    reply = handle_local_sensor_payload(
        pipe_handle, payload, ingress=ingress, policy_provider=policy_provider,
        on_observation=on_observation, received_at=received_at,
        on_security_event=on_security_event,
    )
    write_pipe_frame(pipe_handle, reply.model_dump_json().encode("utf-8"))
    return reply


def handle_local_sensor_payload(
    pipe_handle: object,
    payload: bytes,
    *,
    ingress: ActivityIngress,
    policy_provider: Callable[[], EndpointPolicyV1 | None],
    on_observation: Callable[[ActivityObservationV1], None],
    on_security_event: Callable[[SecurityEventV1], bool] | None = None,
    received_at: datetime | None = None,
) -> BrowserBridgeAckV1:
    """Authorize the writer of an already-framed request before projection."""
    try:
        identity = authorize_pipe_client(pipe_handle)
    except LocalIpcRejected:
        reply = _ack("IDENTITY_MISMATCH")
    else:
        try:
            current_policy = policy_provider()
            reply, observation = ingress.ingest(
                payload, identity=identity, user_login=resolve_user_login(identity),
                policy=current_policy, received_at=received_at or datetime.now(UTC),
                on_security_event=on_security_event,
            )
            if reply.accepted and observation is not None:
                on_observation(observation)
        except Exception:
            reply = _ack("IPC_UNAVAILABLE")
    return reply


def create_activity_pipe_listener(
    *,
    ingress: ActivityIngress,
    policy_provider: Callable[[], EndpointPolicyV1 | None],
    on_observation: Callable[[ActivityObservationV1], None],
    on_security_event: Callable[[SecurityEventV1], bool] | None = None,
    pipe_name: str = PIPE_NAME,
) -> LocalSensorPipeListener:
    """Bind the bounded pipe to OS-authorized, policy-gated activity projection."""
    def on_frame(pipe_handle: object, payload: bytes) -> bytes:
        reply = handle_local_sensor_payload(
            pipe_handle, payload, ingress=ingress, policy_provider=policy_provider,
            on_observation=on_observation,
            on_security_event=on_security_event,
        )
        return reply.model_dump_json().encode("utf-8")

    return LocalSensorPipeListener(on_frame, pipe_name=pipe_name)
