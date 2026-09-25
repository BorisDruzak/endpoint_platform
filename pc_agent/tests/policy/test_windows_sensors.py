"""Policy ACK follows the helper's result, not its attempted registry writes."""

from __future__ import annotations

import pytest

from pc_agent.policy.runtime import PolicyApplicationError
from pc_agent.policy.windows_sensors import apply_windows_policy_sensors
from pc_agent.runtime.application import _policy_applicator_for
from pc_agent.tests.policy.test_runtime import _delivery


def _browser_policy(*, mode: str, required: bool = True):
    disabled = _delivery(active=False).policy
    return disabled.model_copy(
        update={
            "browser_sensor": disabled.browser_sensor.model_copy(
                update={
                    "required": required,
                    "deployment_mode": mode,
                }
            ),
        }
    )


def test_windows_runtime_selects_browser_policy_applicator_only_on_windows() -> None:
    assert _policy_applicator_for("nt") is apply_windows_policy_sensors
    assert _policy_applicator_for("posix") is None


@pytest.mark.asyncio
async def test_agent_managed_applies_both_fixed_browser_policies(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "APPLIED",
    )
    await apply_windows_policy_sensors(_browser_policy(mode="agent_managed"))
    assert calls == [("apply", "chrome"), ("apply", "yandex")]


@pytest.mark.asyncio
async def test_policy_helper_startup_pipe_is_retried_before_error_ack(monkeypatch) -> None:
    class PipeNotReady(Exception):
        winerror = 2

    calls: list[tuple[str, str]] = []

    def helper(operation: str, family: str) -> str:
        calls.append((operation, family))
        if len(calls) <= 2:
            raise PipeNotReady("helper pipe has not been created")
        return "APPLIED"

    monkeypatch.setattr("pc_agent.policy.windows_sensors.send_policy_request", helper)
    await apply_windows_policy_sensors(_browser_policy(mode="agent_managed"))
    assert calls == [
        ("apply", "chrome"),
        ("apply", "chrome"),
        ("apply", "chrome"),
        ("apply", "yandex"),
    ]


@pytest.mark.asyncio
async def test_policy_helper_access_denied_fails_without_retry(monkeypatch) -> None:
    class AccessDenied(Exception):
        winerror = 5

    calls: list[tuple[str, str]] = []

    def helper(operation: str, family: str) -> str:
        calls.append((operation, family))
        raise AccessDenied("helper refused the caller")

    monkeypatch.setattr("pc_agent.policy.windows_sensors.send_policy_request", helper)
    with pytest.raises(PolicyApplicationError, match="BROWSER_POLICY_HELPER_UNAVAILABLE"):
        await apply_windows_policy_sensors(_browser_policy(mode="agent_managed"))
    assert calls == [("apply", "chrome")]


@pytest.mark.asyncio
async def test_policy_helper_missing_pipe_retries_for_bounded_time(monkeypatch) -> None:
    class PipeNotReady(Exception):
        winerror = 2

    calls: list[tuple[str, str]] = []

    def helper(operation: str, family: str) -> str:
        calls.append((operation, family))
        raise PipeNotReady("helper never started")

    monkeypatch.setattr("pc_agent.policy.windows_sensors.send_policy_request", helper)
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors._HELPER_STARTUP_RETRY_DELAYS", (0, 0),
    )
    with pytest.raises(PolicyApplicationError, match="BROWSER_POLICY_HELPER_UNAVAILABLE"):
        await apply_windows_policy_sensors(_browser_policy(mode="agent_managed"))
    assert calls == [("apply", "chrome")] * 3


@pytest.mark.asyncio
async def test_external_managed_relinquishes_only_owned_policy(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: (
            calls.append((operation, family)) or "EXTERNALLY_MANAGED"
        ),
    )
    await apply_windows_policy_sensors(_browser_policy(mode="external_managed"))
    assert calls == [("relinquish", "chrome"), ("relinquish", "yandex")]


@pytest.mark.asyncio
async def test_unavailable_activity_fails_before_any_helper_side_effect(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "APPLIED",
    )
    with pytest.raises(PolicyApplicationError, match="SENSOR_NOT_READY"):
        await apply_windows_policy_sensors(
            _delivery(active=True).policy,
            browser_audit_available=True, usb_available=True, print_available=True,
        )
    assert calls == []


@pytest.mark.asyncio
async def test_unavailable_browser_audit_fails_before_any_helper_side_effect(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "APPLIED",
    )
    with pytest.raises(PolicyApplicationError, match="SENSOR_NOT_READY"):
        await apply_windows_policy_sensors(
            _delivery(active=True).policy,
            activity_available=True, usb_available=True, print_available=True,
        )
    assert calls == []


@pytest.mark.asyncio
async def test_active_policy_applies_after_local_activity_and_dlp_sources_are_ready(
    monkeypatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "APPLIED",
    )
    await apply_windows_policy_sensors(
        _delivery(active=True).policy,
        activity_available=True,
        browser_audit_available=True,
        usb_available=True,
        print_available=True,
    )
    assert calls == [("apply", "chrome"), ("apply", "yandex")]


@pytest.mark.asyncio
async def test_usb_audit_requires_live_notification_source(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "EXTERNALLY_MANAGED",
    )
    disabled = _delivery(active=False).policy
    policy = disabled.model_copy(update={
        "dlp": disabled.dlp.model_copy(update={"usb_device_events": "audit"}),
    })
    with pytest.raises(PolicyApplicationError, match="SENSOR_NOT_READY"):
        await apply_windows_policy_sensors(policy, usb_available=False)
    assert calls == []
    await apply_windows_policy_sensors(policy, usb_available=True)
    assert calls == [("relinquish", "chrome"), ("relinquish", "yandex")]


@pytest.mark.asyncio
async def test_print_audit_requires_live_notification_source(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "pc_agent.policy.windows_sensors.send_policy_request",
        lambda operation, family: calls.append((operation, family)) or "EXTERNALLY_MANAGED",
    )
    disabled = _delivery(active=False).policy
    policy = disabled.model_copy(update={
        "dlp": disabled.dlp.model_copy(update={"print_events": "audit"}),
    })
    with pytest.raises(PolicyApplicationError, match="SENSOR_NOT_READY"):
        await apply_windows_policy_sensors(policy, print_available=False)
    assert calls == []
    await apply_windows_policy_sensors(policy, print_available=True)
    assert calls == [("relinquish", "chrome"), ("relinquish", "yandex")]


@pytest.mark.asyncio
async def test_conflict_from_helper_prevents_policy_application(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def conflict(operation: str, family: str) -> str:
        calls.append((operation, family))
        return "POLICY_CONFLICT" if family == "yandex" else "APPLIED"

    monkeypatch.setattr("pc_agent.policy.windows_sensors.send_policy_request", conflict)
    with pytest.raises(PolicyApplicationError, match="POLICY_CONFLICT"):
        await apply_windows_policy_sensors(_browser_policy(mode="agent_managed"))
    assert calls == [("apply", "chrome"), ("apply", "yandex")]
