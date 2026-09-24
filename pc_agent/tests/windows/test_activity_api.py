"""OS-authorized local sensor data is projected only under applied Policy."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows.activity_api import ActivityIngress
from pc_agent.platform.windows.local_ipc import ClientIdentity
from pc_agent.platform.windows.local_sensor_protocol import (
    LocalBrowserEnvelopeV1,
    LocalUserSessionEnvelopeV1,
    serialize_local_sensor_payload,
)
from pc_agent.platform.windows.user_sensor import UserSessionSampleV1
from pc_agent.browser_protocol import (
    BrowserContextV1,
    BrowserHeartbeatV1,
    BrowserUploadV1,
)


EXTENSION_ID = "a" * 32
NOW = datetime(2026, 9, 25, tzinfo=UTC)
IDENTITY = ClientIdentity(
    user_sid="S-1-5-21-123-456-789-1001", logon_sid="S-1-5-5-10-20",
    token_session_id=3, group_sids=frozenset({"S-1-5-4", "S-1-5-5-10-20"}),
)
OTHER_IDENTITY = ClientIdentity(
    user_sid="S-1-5-21-123-456-789-1002", logon_sid="S-1-5-5-10-21",
    token_session_id=4, group_sids=frozenset({"S-1-5-4", "S-1-5-5-10-21"}),
)


def policy(*, activity_enabled: bool = True, browser_context: bool = True) -> EndpointPolicyV1:
    return EndpointPolicyV1.model_validate({
        "schema_version": "endpoint_policy_v1", "policy_id": str(uuid4()), "policy_version": 1,
        "activity": {
            "enabled": activity_enabled, "idle_threshold_seconds": 60,
            "foreground_application": True, "browser_context": browser_context,
        },
        "dlp": {
            "usb_device_events": "disabled", "removable_write_events": "disabled",
            "print_events": "disabled", "browser_upload_events": "audit",
            "browser_paste_events": "disabled",
        },
        "browser_sensor": {"required": True, "deployment_mode": "external_managed"},
        "event_retention": {"security_event_days": 30},
    })


def user_payload(idle_seconds: int) -> bytes:
    return serialize_local_sensor_payload(LocalUserSessionEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="user_session",
        sample=UserSessionSampleV1(
            schema_version="user_session_sample_v1", desktop_state="UNLOCKED",
            idle_seconds=idle_seconds,
            foreground={"process_name": "chrome.exe", "application_category": "browser"},
        ),
    ))


def browser_payload(message, *, extension_id: str = EXTENSION_ID) -> bytes:
    return serialize_local_sensor_payload(LocalBrowserEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="browser",
        extension_id=extension_id, message=message,
    ))


def test_user_sample_uses_server_policy_idle_threshold_and_os_login() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    active_ack, active = ingress.ingest(
        user_payload(59), identity=IDENTITY, user_login="CORP\\ivanova",
        policy=current_policy, received_at=NOW,
    )
    idle_ack, idle = ingress.ingest(
        user_payload(60), identity=IDENTITY, user_login="CORP\\ivanova",
        policy=current_policy, received_at=NOW + timedelta(seconds=1),
    )
    assert active_ack.accepted and idle_ack.accepted
    assert active.session_state == "ACTIVE" and active.idle_seconds == 59
    assert idle.session_state == "IDLE" and idle.idle_seconds == 60
    assert idle.user_login == "CORP\\ivanova"
    assert idle.foreground.process_name == "chrome.exe"


def test_browser_context_stays_in_its_os_logon_session() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    heartbeat = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.1.0", browser_family="chrome", observed_at=NOW,
    )
    context = BrowserContextV1(
        schema_version="browser_sensor_context_v1", protocol_version=1,
        browser_family="chrome", scheme="https", origin="https://example.test",
        domain="example.test", tab_active=True, observed_at=NOW,
    )
    ingress.ingest(browser_payload(heartbeat), identity=IDENTITY, user_login="u1",
                   policy=current_policy, received_at=NOW)
    ack, observed = ingress.ingest(
        browser_payload(context), identity=IDENTITY, user_login="u1",
        policy=current_policy, received_at=NOW + timedelta(seconds=1),
    )
    assert ack.accepted
    assert observed.browser.domain == "example.test"
    assert observed.browser.extension_version == "0.1.0"
    other_ack, other = ingress.ingest(
        user_payload(1), identity=OTHER_IDENTITY, user_login="u2",
        policy=current_policy, received_at=NOW + timedelta(seconds=2),
    )
    assert other_ack.accepted and other.browser is None


def test_heartbeat_does_not_keep_old_origin_indefinitely() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    context = BrowserContextV1(
        schema_version="browser_sensor_context_v1", protocol_version=1,
        browser_family="chrome", scheme="https", origin="https://example.test",
        domain="example.test", tab_active=True, observed_at=NOW,
    )
    heartbeat = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.1.0", browser_family="chrome", observed_at=NOW,
    )
    ingress.ingest(browser_payload(context), identity=IDENTITY, user_login="u1",
                   policy=current_policy, received_at=NOW)
    ack, observed = ingress.ingest(
        browser_payload(heartbeat), identity=IDENTITY, user_login="u1",
        policy=current_policy, received_at=NOW + timedelta(minutes=3),
    )
    assert ack.accepted
    assert observed.browser.sensor_state == "ACTIVE"
    assert observed.browser.origin is None and observed.browser.domain is None


def test_wrong_extension_and_unapplied_policy_fail_closed() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    heartbeat = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.1.0", browser_family="chrome", observed_at=NOW,
    )
    wrong_ack, wrong = ingress.ingest(
        browser_payload(heartbeat, extension_id="b" * 32), identity=IDENTITY,
        user_login="u1", policy=policy(), received_at=NOW,
    )
    no_policy_ack, no_policy = ingress.ingest(
        user_payload(1), identity=IDENTITY, user_login="u1", policy=None,
        received_at=NOW,
    )
    assert wrong_ack.error_code == "IDENTITY_MISMATCH" and wrong is None
    assert no_policy_ack.error_code == "SENSOR_NOT_READY" and no_policy is None


def test_dlp_event_is_not_acknowledged_before_durable_spool() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    upload = BrowserUploadV1(
        schema_version="browser_sensor_event_v1", protocol_version=1,
        event_identifier=uuid4(), browser_family="chrome",
        destination_origin="https://example.test", destination_domain="example.test",
        observed_at=NOW, event_type="BROWSER_UPLOAD", file_count=1,
        total_bytes=42, mime_categories=["document"],
    )
    ack, observed = ingress.ingest(
        browser_payload(upload), identity=IDENTITY, user_login="u1",
        policy=policy(), received_at=NOW,
    )
    assert ack.error_code == "SENSOR_NOT_READY" and observed is None


def test_disabled_activity_does_not_emit_user_observation() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    ack, observed = ingress.ingest(
        user_payload(5), identity=IDENTITY, user_login="u1",
        policy=policy(activity_enabled=False), received_at=NOW,
    )
    assert ack.error_code == "POLICY_DISABLED" and observed is None


def test_user_sensor_can_run_before_signed_browser_identity_is_pinned() -> None:
    ingress = ActivityIngress(expected_extension_id=None)
    current_policy = policy()
    user_ack, user_observation = ingress.ingest(
        user_payload(5), identity=IDENTITY, user_login="u1",
        policy=current_policy, received_at=NOW,
    )
    heartbeat = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.1.0", browser_family="chrome", observed_at=NOW,
    )
    browser_ack, browser_observation = ingress.ingest(
        browser_payload(heartbeat), identity=IDENTITY, user_login="u1",
        policy=current_policy, received_at=NOW,
    )
    assert user_ack.accepted and user_observation.session_state == "ACTIVE"
    assert browser_ack.error_code == "SENSOR_NOT_READY"
    assert browser_observation is None


def test_session_projection_has_bounded_memory_under_many_logons() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    for number in range(130):
        identity = ClientIdentity(
            user_sid=f"S-1-5-21-123-456-789-{1000 + number}",
            logon_sid=f"S-1-5-5-10-{number + 1}", token_session_id=number + 1,
            group_sids=frozenset({"S-1-5-4", f"S-1-5-5-10-{number + 1}"}),
        )
        ack, _observation = ingress.ingest(
            user_payload(1), identity=identity, user_login=None,
            policy=current_policy, received_at=NOW,
        )
        assert ack.accepted
    assert len(ingress._sessions) == 128
