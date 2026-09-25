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
    BrowserPasteV1,
    BrowserUploadV1,
)
from endpoint_contracts.security_events import BrowserPasteEventV1, BrowserUploadEventV1


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


def test_latest_user_sample_is_policy_scoped_and_rejected_samples_do_not_count() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    assert ingress.latest_user_sample_at(current_policy) is None
    accepted, _ = ingress.ingest(
        user_payload(12), identity=IDENTITY, user_login="u",
        policy=current_policy, received_at=NOW,
    )
    assert accepted.accepted
    assert ingress.latest_user_sample_at(current_policy) == NOW
    rotated = current_policy.model_copy(update={"policy_version": 2})
    assert ingress.latest_user_sample_at(rotated) is None
    disabled = policy(activity_enabled=False)
    rejected, _ = ingress.ingest(
        user_payload(10), identity=IDENTITY, user_login="u",
        policy=disabled, received_at=NOW + timedelta(seconds=1),
    )
    assert not rejected.accepted
    assert ingress.latest_user_sample_at(disabled) is None


def test_browser_activity_after_policy_rotation_does_not_reuse_old_user_sample() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    original = policy()
    ingress.ingest(
        user_payload(12), identity=IDENTITY, user_login="u",
        policy=original, received_at=NOW,
    )
    rotated = original.model_copy(update={"policy_version": 2})
    heartbeat = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.1.0", browser_family="chrome", observed_at=NOW,
    )
    ack, observation = ingress.ingest(
        browser_payload(heartbeat), identity=IDENTITY, user_login="u",
        policy=rotated, received_at=NOW + timedelta(seconds=1),
    )
    assert ack.accepted
    assert observation is not None
    assert observation.session_state == "UNKNOWN"
    assert observation.idle_seconds is None


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


def test_heartbeats_coalesce_by_family_and_applied_policy() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    for family, delay, version, install_type in (
        ("chrome", 0, "0.1.0", "unknown"),
        ("chrome", 60, "0.2.0", "admin"),
        ("yandex", 90, "0.1.0", "normal"),
    ):
        heartbeat = BrowserHeartbeatV1(
            schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
            extension_version=version, browser_family=family, observed_at=NOW,
            install_type=install_type,
        )
        ack, _ = ingress.ingest(
            browser_payload(heartbeat), identity=IDENTITY, user_login="u1",
            policy=current_policy, received_at=NOW + timedelta(seconds=delay),
        )
        assert ack.accepted
    facts = ingress.latest_heartbeats(current_policy)
    assert facts["chrome"].extension_version == "0.2.0"
    assert facts["chrome"].last_seen_at == NOW + timedelta(seconds=60)
    assert facts["chrome"].install_type == "admin"
    assert facts["yandex"].last_seen_at == NOW + timedelta(seconds=90)
    assert facts["yandex"].install_type == "normal"
    assert ingress.latest_heartbeats(policy()) == {}

    bad = BrowserHeartbeatV1(
        schema_version="browser_sensor_heartbeat_v1", protocol_version=1,
        extension_version="0.3.0", browser_family="chrome", observed_at=NOW,
    )
    rejected, _ = ingress.ingest(
        browser_payload(bad, extension_id="b" * 32), identity=IDENTITY,
        user_login="u1", policy=current_policy,
        received_at=NOW + timedelta(seconds=120),
    )
    assert rejected.error_code == "IDENTITY_MISMATCH"
    assert ingress.latest_heartbeats(current_policy)["chrome"].extension_version == "0.2.0"


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


def test_browser_upload_is_acknowledged_only_after_safe_event_is_stored() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    current_policy = policy()
    identifier = uuid4()
    upload = BrowserUploadV1(
        schema_version="browser_sensor_event_v1", protocol_version=1,
        event_identifier=identifier, browser_family="yandex",
        destination_origin="https://example.test",
        destination_domain="example.test", observed_at=NOW,
        event_type="BROWSER_UPLOAD", file_count=2, total_bytes=42,
        mime_categories=["document"],
    )
    stored = []
    ack, observation = ingress.ingest(
        browser_payload(upload), identity=IDENTITY, user_login="CORP\\user",
        policy=current_policy, received_at=NOW,
        on_security_event=lambda event: stored.append(event) or True,
    )
    assert ack.accepted and observation is None
    assert len(stored) == 1
    event = stored[0]
    assert isinstance(event, BrowserUploadEventV1)
    assert event.event_identifier == identifier
    assert event.policy_id == current_policy.policy_id
    assert event.policy_version == current_policy.policy_version
    assert event.user_login == "CORP\\user"
    assert event.safe_metadata.model_dump(exclude_none=True) == {
        "domain": "example.test", "origin": "https://example.test",
        "browser_family": "yandex", "file_count": 2, "total_bytes": 42,
        "mime_categories": ["document"],
    }


def test_browser_event_fails_closed_when_spool_rejects_it() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    upload = BrowserUploadV1(
        schema_version="browser_sensor_event_v1", protocol_version=1,
        event_identifier=uuid4(), browser_family="chrome",
        destination_origin="https://example.test",
        destination_domain="example.test", observed_at=NOW,
        event_type="BROWSER_UPLOAD", file_count=1, total_bytes=0,
        mime_categories=["other"],
    )
    ack, observation = ingress.ingest(
        browser_payload(upload), identity=IDENTITY, user_login=None,
        policy=policy(), received_at=NOW,
        on_security_event=lambda _event: False,
    )
    assert ack.error_code == "IPC_UNAVAILABLE" and observation is None


def test_disabled_browser_paste_never_enters_spool() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    paste = BrowserPasteV1(
        schema_version="browser_sensor_event_v1", protocol_version=1,
        event_identifier=uuid4(), browser_family="chrome",
        destination_origin="https://example.test",
        destination_domain="example.test", observed_at=NOW,
        event_type="BROWSER_PASTE", clipboard_types=["text"],
    )
    stored = []
    ack, observation = ingress.ingest(
        browser_payload(paste), identity=IDENTITY, user_login=None,
        policy=policy(), received_at=NOW,
        on_security_event=lambda event: stored.append(event) or True,
    )
    assert ack.error_code == "POLICY_DISABLED" and observation is None
    assert stored == []


def test_browser_paste_records_types_without_clipboard_content() -> None:
    ingress = ActivityIngress(expected_extension_id=EXTENSION_ID)
    document = policy().model_dump(mode="json")
    document["dlp"]["browser_paste_events"] = "audit"
    current_policy = EndpointPolicyV1.model_validate(document)
    paste = BrowserPasteV1(
        schema_version="browser_sensor_event_v1", protocol_version=1,
        event_identifier=uuid4(), browser_family="chrome",
        destination_origin="https://example.test",
        destination_domain="example.test", observed_at=NOW,
        event_type="BROWSER_PASTE", clipboard_types=["text", "html"],
    )
    stored = []
    ack, observation = ingress.ingest(
        browser_payload(paste), identity=IDENTITY, user_login="CORP\\user",
        policy=current_policy, received_at=NOW,
        on_security_event=lambda event: stored.append(event) or True,
    )
    assert ack.accepted and observation is None
    assert len(stored) == 1 and isinstance(stored[0], BrowserPasteEventV1)
    assert stored[0].safe_metadata.clipboard_types == ["text", "html"]
    assert "content" not in stored[0].model_dump_json().lower()


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
