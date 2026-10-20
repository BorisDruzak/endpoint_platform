"""Synthetic, disposable Activity history; never imported by production."""
from datetime import timedelta
from uuid import uuid4

from endpoint_contracts.activity import ActivityObservationV1
from endpoint_server.activity.analytics_policy import AnalyticsPolicy
from endpoint_server.activity.analytics_store import record_observation, rebuild_daily


async def seed_activity_analytics(session, device_id, now):
    start = now - timedelta(seconds=1110)
    samples = []
    for second in range(0, 601, 15):
        state = 'IDLE' if 360 <= second < 450 else 'ACTIVE'
        process = 'WINWORD.EXE' if second < 180 else 'EXCEL.EXE' if second < 360 else 'chrome.exe'
        samples.append((second, state, process))
    for second in range(900, 1081, 15):
        state = 'LOCKED' if second < 960 else 'DISCONNECTED' if second < 1020 else 'ACTIVE'
        samples.append((second, state, 'WINWORD.EXE'))
    for second, state, process in samples:
        obs = ActivityObservationV1(schema_version='activity_observation_v1', observation_id=uuid4(),
            observed_at=start + timedelta(seconds=second), user_login='EXAMPLE\\Synthetic.Employee',
            session_state=state, idle_seconds=(900 if state == 'IDLE' else 0) if state in {'ACTIVE', 'IDLE'} else None,
            foreground={'process_name': process, 'application_category': 'other'} if state in {'ACTIVE', 'IDLE'} else None)
        await record_observation(session, device_id, obs, state=state, policy_version_id=None, policy=AnalyticsPolicy())
    await rebuild_daily(session, policy=AnalyticsPolicy(), now=now)
