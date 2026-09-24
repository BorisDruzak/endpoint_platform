"""The service reads, impersonates, projects and ACKs one local sensor frame."""

from datetime import UTC, datetime
from uuid import uuid4

from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from pc_agent.platform.windows import activity_api
from pc_agent.platform.windows.activity_api import ActivityIngress, handle_local_sensor_connection
from pc_agent.platform.windows.local_ipc import ClientIdentity, LocalIpcRejected
from pc_agent.platform.windows.local_sensor_protocol import (
    LocalUserSessionEnvelopeV1, serialize_local_sensor_payload,
)
from pc_agent.platform.windows.user_sensor import UserSessionSampleV1


NOW = datetime(2026, 9, 25, tzinfo=UTC)
EXTENSION_ID = "a" * 32
IDENTITY = ClientIdentity(
    user_sid="S-1-5-21-1-2-3-1001", logon_sid="S-1-5-5-1-2", token_session_id=1,
    group_sids=frozenset({"S-1-5-4", "S-1-5-5-1-2"}),
)


def policy() -> EndpointPolicyV1:
    return EndpointPolicyV1.model_validate({
        "schema_version": "endpoint_policy_v1", "policy_id": str(uuid4()), "policy_version": 1,
        "activity": {"enabled": True, "idle_threshold_seconds": 60,
                     "foreground_application": True, "browser_context": True},
        "dlp": {"usb_device_events": "disabled", "removable_write_events": "disabled",
                "print_events": "disabled", "browser_upload_events": "disabled",
                "browser_paste_events": "disabled"},
        "browser_sensor": {"required": False, "deployment_mode": "external_managed"},
        "event_retention": {"security_event_days": 30},
    })


def user_payload(idle_seconds: int) -> bytes:
    return serialize_local_sensor_payload(LocalUserSessionEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="user_session",
        sample=UserSessionSampleV1(
            schema_version="user_session_sample_v1", desktop_state="UNLOCKED",
            idle_seconds=idle_seconds,
        ),
    ))


def test_receiver_reads_before_impersonating_and_sends_one_ack(monkeypatch) -> None:
    order: list[str] = []
    sent = []
    written = []
    monkeypatch.setattr(activity_api, "read_pipe_frame", lambda _pipe: order.append("read") or user_payload(3))
    monkeypatch.setattr(activity_api, "authorize_pipe_client", lambda _pipe: order.append("authorize") or IDENTITY)
    monkeypatch.setattr(activity_api, "resolve_user_login", lambda _identity: "CORP\\user")
    monkeypatch.setattr(activity_api, "write_pipe_frame", lambda _pipe, body: written.append(body))

    reply = handle_local_sensor_connection(
        object(), ingress=ActivityIngress(expected_extension_id=EXTENSION_ID),
        policy_provider=policy, on_observation=sent.append, received_at=NOW,
    )
    assert order == ["read", "authorize"]
    assert reply.accepted and len(written) == 1 and len(sent) == 1
    assert sent[0].user_login == "CORP\\user"
    assert b"CORP" not in written[0]


def test_receiver_rejects_wrong_os_session_without_projecting(monkeypatch) -> None:
    sent = []
    written = []
    monkeypatch.setattr(activity_api, "read_pipe_frame", lambda _pipe: user_payload(3))
    def reject(_pipe):
        raise LocalIpcRejected("private SID")
    monkeypatch.setattr(activity_api, "authorize_pipe_client", reject)
    monkeypatch.setattr(activity_api, "write_pipe_frame", lambda _pipe, body: written.append(body))
    reply = handle_local_sensor_connection(
        object(), ingress=ActivityIngress(expected_extension_id=EXTENSION_ID),
        policy_provider=policy, on_observation=sent.append, received_at=NOW,
    )
    assert reply.error_code == "IDENTITY_MISMATCH"
    assert sent == [] and len(written) == 1
    assert b"private SID" not in written[0]


def test_receiver_does_not_ack_success_when_handoff_fails(monkeypatch) -> None:
    monkeypatch.setattr(activity_api, "read_pipe_frame", lambda _pipe: user_payload(3))
    monkeypatch.setattr(activity_api, "authorize_pipe_client", lambda _pipe: IDENTITY)
    monkeypatch.setattr(activity_api, "resolve_user_login", lambda _identity: None)
    monkeypatch.setattr(activity_api, "write_pipe_frame", lambda _pipe, _body: None)
    def unavailable(_observation):
        raise RuntimeError("sensitive runtime detail")
    reply = handle_local_sensor_connection(
        object(), ingress=ActivityIngress(expected_extension_id=EXTENSION_ID),
        policy_provider=policy, on_observation=unavailable, received_at=NOW,
    )
    assert reply.error_code == "IPC_UNAVAILABLE"
