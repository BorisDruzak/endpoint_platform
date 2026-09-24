"""Policy-gated projection of locally authorized user and browser observations."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from endpoint_contracts.activity import (
    ActivityObservationV1, BrowserActivityV1,
)
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.browser_protocol import (
    BrowserBridgeAckV1, BrowserContextV1, BrowserHeartbeatV1, BrowserHelloV1,
    BrowserPasteV1, BrowserUploadV1,
)

from .local_ipc import (
    ClientIdentity, LocalIpcRejected, authorize_pipe_client, read_pipe_frame,
    resolve_user_login, write_pipe_frame,
)
from .local_sensor_protocol import (
    LocalSensorProtocolError,
    LocalUserSessionEnvelopeV1, parse_local_sensor_payload,
)
from .user_sensor import UserSessionSampleV1


_SAMPLE_FRESHNESS = timedelta(minutes=2)
_MAX_TRACKED_SESSIONS = 128


@dataclass
class _SessionProjection:
    sample: UserSessionSampleV1 | None = None
    sampled_at: datetime | None = None
    browsers: dict[str, tuple[BrowserActivityV1, datetime]] = field(default_factory=dict)
    context_seen_at: dict[str, datetime] = field(default_factory=dict)


def _ack(error_code: str = "OK") -> BrowserBridgeAckV1:
    return BrowserBridgeAckV1(
        schema_version="browser_bridge_ack_v1",
        accepted=error_code == "OK", error_code=error_code,
    )


class ActivityIngress:
    """Hold only recent, session-isolated projection state in Agent memory."""

    def __init__(self, *, expected_extension_id: str) -> None:
        if not isinstance(expected_extension_id, str) or len(expected_extension_id) != 32 or any(
            char not in "abcdefghijklmnop" for char in expected_extension_id
        ):
            raise ValueError("invalid pinned Browser Sensor extension ID")
        self._extension_id = expected_extension_id
        self._sessions: OrderedDict[tuple[str, str, int], _SessionProjection] = OrderedDict()

    def _session(self, key: tuple[str, str, int]) -> _SessionProjection:
        existing = self._sessions.get(key)
        if existing is not None:
            self._sessions.move_to_end(key)
            return existing
        projection = _SessionProjection()
        self._sessions[key] = projection
        if len(self._sessions) > _MAX_TRACKED_SESSIONS:
            self._sessions.popitem(last=False)
        return projection

    def ingest(
        self,
        payload: bytes,
        *,
        identity: ClientIdentity,
        user_login: str | None,
        policy: EndpointPolicyV1 | None,
        received_at: datetime,
    ) -> tuple[BrowserBridgeAckV1, ActivityObservationV1 | None]:
        if received_at.tzinfo is None or received_at.utcoffset() is None:
            raise ValueError("local sensor receipt time must be timezone-aware")
        if policy is None:
            return _ack("SENSOR_NOT_READY"), None
        try:
            envelope = parse_local_sensor_payload(payload)
        except LocalSensorProtocolError as error:
            return _ack(error.code), None
        now = received_at.astimezone(UTC)
        key = (identity.user_sid, identity.logon_sid, identity.token_session_id)
        if isinstance(envelope, LocalUserSessionEnvelopeV1):
            if not policy.activity.enabled:
                return _ack("POLICY_DISABLED"), None
            projection = self._session(key)
            projection.sample = envelope.sample
            projection.sampled_at = now
            return _ack(), self._project(projection, user_login, policy, now)

        if envelope.extension_id != self._extension_id:
            return _ack("IDENTITY_MISMATCH"), None
        message = envelope.message
        if isinstance(message, (BrowserUploadV1, BrowserPasteV1)):
            mode = (
                policy.dlp.browser_upload_events if isinstance(message, BrowserUploadV1)
                else policy.dlp.browser_paste_events
            )
            return _ack("SENSOR_NOT_READY" if mode == "audit" else "POLICY_DISABLED"), None
        if not (
            policy.browser_sensor.required
            or (policy.activity.enabled and policy.activity.browser_context)
        ):
            return _ack("POLICY_DISABLED"), None
        projection = self._session(key)
        previous = projection.browsers.get(message.browser_family)
        prior_browser = previous[0] if previous else None
        version = (
            message.extension_version
            if isinstance(message, (BrowserHelloV1, BrowserHeartbeatV1))
            else prior_browser.extension_version if prior_browser else None
        )
        if isinstance(message, BrowserContextV1):
            origin, domain = message.origin, message.domain
            projection.context_seen_at[message.browser_family] = now
        else:
            context_at = projection.context_seen_at.get(message.browser_family)
            context_fresh = context_at is not None and timedelta(0) <= now - context_at <= _SAMPLE_FRESHNESS
            origin = prior_browser.origin if prior_browser and context_fresh else None
            domain = prior_browser.domain if prior_browser and context_fresh else None
        projection.browsers[message.browser_family] = (
            BrowserActivityV1(
                browser_family=message.browser_family,
                origin=origin, domain=domain,
                sensor_state="ACTIVE", extension_version=version,
                last_seen_at=now,
            ),
            now,
        )
        if not (policy.activity.enabled and policy.activity.browser_context):
            return _ack(), None
        return _ack(), self._project(projection, user_login, policy, now)

    @staticmethod
    def _project(
        projection: _SessionProjection,
        user_login: str | None,
        policy: EndpointPolicyV1,
        now: datetime,
    ) -> ActivityObservationV1:
        sample = (
            projection.sample
            if projection.sampled_at is not None
            and timedelta(0) <= now - projection.sampled_at <= _SAMPLE_FRESHNESS
            else None
        )
        if sample is None:
            state = "UNKNOWN"
            idle = None
            foreground = None
        elif sample.desktop_state == "UNLOCKED":
            idle = sample.idle_seconds
            state = "IDLE" if idle >= policy.activity.idle_threshold_seconds else "ACTIVE"
            foreground = sample.foreground if policy.activity.foreground_application else None
        else:
            state = sample.desktop_state
            idle = None
            foreground = None
        browser = None
        if policy.activity.browser_context:
            current = [
                value for value, seen_at in projection.browsers.values()
                if timedelta(0) <= now - seen_at <= _SAMPLE_FRESHNESS
            ]
            if current:
                browser = max(current, key=lambda item: item.last_seen_at)
        return ActivityObservationV1(
            schema_version="activity_observation_v1", observation_id=uuid4(),
            observed_at=now, user_login=user_login, session_state=state,
            idle_seconds=idle, foreground=foreground, browser=browser,
        )


def handle_local_sensor_connection(
    pipe_handle: object,
    *,
    ingress: ActivityIngress,
    policy_provider: Callable[[], EndpointPolicyV1 | None],
    on_observation: Callable[[ActivityObservationV1], None],
    received_at: datetime | None = None,
) -> BrowserBridgeAckV1 | None:
    """Read exactly one frame, then impersonate its writer before projection."""
    try:
        payload = read_pipe_frame(pipe_handle)
    except LocalIpcRejected:
        return None  # A broken frame cannot be safely ACKed on the same stream.
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
            )
            if reply.accepted and observation is not None:
                on_observation(observation)
        except Exception:
            reply = _ack("IPC_UNAVAILABLE")
    write_pipe_frame(pipe_handle, reply.model_dump_json().encode("utf-8"))
    return reply
