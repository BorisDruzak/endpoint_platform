"""Windows and Linux must share policy projection and content-free envelopes."""
from datetime import UTC, datetime


def test_sensor_models_keep_windows_compatibility_imports():
    from pc_agent.local_sensor_protocol import UserSessionSampleV1, LocalUserSessionEnvelopeV1
    from pc_agent.platform.windows.user_sensor import UserSessionSampleV1 as WindowsSample
    from pc_agent.platform.windows.local_sensor_protocol import LocalUserSessionEnvelopeV1 as WindowsEnvelope

    assert WindowsSample is UserSessionSampleV1
    assert WindowsEnvelope is LocalUserSessionEnvelopeV1


def test_shared_projection_supports_linux_session_keys_and_policy_idle_threshold():
    from pc_agent.activity_ingress import ActivityIngress
    from pc_agent.local_sensor_protocol import UserSessionSampleV1, LocalUserSessionEnvelopeV1, serialize_local_sensor_payload
    from pc_agent.tests.windows.test_activity_api import policy

    current = policy(browser_context=False)
    payload = serialize_local_sensor_payload(LocalUserSessionEnvelopeV1(
        schema_version="local_sensor_envelope_v1", source="user_session",
        sample=UserSessionSampleV1(schema_version="user_session_sample_v1", desktop_state="UNLOCKED", idle_seconds=60),
    ))
    reply, observation = ActivityIngress(expected_extension_id=None).ingest(
        payload, session_key=("linux", "c2", 2000), user_login="user@domain.example",
        policy=current, received_at=datetime.now(UTC),
    )
    assert reply.accepted and observation.session_state == "IDLE"
    assert observation.user_login == "user@domain.example"
