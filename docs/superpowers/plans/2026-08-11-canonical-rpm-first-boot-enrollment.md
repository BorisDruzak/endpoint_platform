# Canonical RPM First-Boot Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the canonical frozen ALT core enroll with its one-time systemd claim before starting Gateway WSS.

**Architecture:** `pc_agent.runtime.main` reuses the existing fixed-path Linux enrollment gate when the packaged service sets `ENDPOINT_AGENT_ENROLLMENT_REQUIRED=1`. `enrolled`, `already_enrolled`, and post-persistence `handoff_pending` launch the ordinary neutral runtime; all other outcomes preserve exit code `75` and never attempt ordinary transport.

**Tech Stack:** Python 3.12, asyncio, PyInstaller, pytest, ALT RPM.

## Global Constraints

- Accept only the fixed systemd credential names and `https://endpoint.sosnadmin.local` already validated by `linux_enrollment_runtime`.
- Do not log, persist, or expose a claim, service token, or device credential.
- Preserve code `75` for unsuccessful first-boot enrollment and do not connect ordinary Gateway WSS before durable credential creation.

---

### Task 1: Add the runtime regression test

**Files:**
- Modify: `pc_agent/tests/runtime/test_headless_lifecycle.py`
- Modify: `pc_agent/runtime/main.py`

**Interfaces:**
- Consumes: `ENDPOINT_AGENT_ENROLLMENT_REQUIRED=1` and `systemd_runtime_paths()`.
- Produces: a `main()` branch that awaits `run_linux_enrollment_gate()` before calling `run_runtime()`.

- [ ] **Step 1: Write the failing test**

```python
def test_headless_runtime_enrolls_before_starting_gateway(...):
    monkeypatch.setenv("ENDPOINT_AGENT_ENROLLMENT_REQUIRED", "1")
    monkeypatch.setattr(runtime_main, "systemd_runtime_paths", lambda: paths)
    monkeypatch.setattr(runtime_main, "run_linux_enrollment_gate", fake_gate)
    monkeypatch.setattr(runtime_main, "run_runtime", fake_runtime)
    assert runtime_main.main([]) == 0
    assert calls == ["enroll", "runtime"]
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py::test_headless_runtime_enrolls_before_starting_gateway -q`

Expected: FAIL because `runtime.main` does not expose or invoke the enrollment gate.

- [ ] **Step 3: Implement the minimum branch**

Import `EnrollmentOutcome`, `run_linux_enrollment_gate`, and
`systemd_runtime_paths`. Add an async helper that returns `75` when the
service contract is incomplete or its outcome is not `enrolled`,
`already_enrolled`, or `handoff_pending`; otherwise call existing
`run_runtime(settings)`.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py::test_headless_runtime_enrolls_before_starting_gateway -q`

Expected: PASS.

### Task 2: Run regressions and rebuild the artifact

**Files:**
- Verify: `pc_agent/tests/runtime/test_headless_lifecycle.py`
- Verify: `tests/packaging/test_alt_rpm_contract.py`
- Verify: `tests/build/test_linux_headless_artifact.py`

- [ ] **Step 1: Run source verification**

Run: `python -m pytest pc_agent/tests/runtime/test_headless_lifecycle.py tests/packaging/test_alt_rpm_contract.py tests/build/test_linux_headless_artifact.py -q`

- [ ] **Step 2: Build and check RPM**

Run the canonical `packaging/alt/build-rpm.sh` on ALT, then run `rpm -K` and
confirm the fingerprint helper remains in its payload.

- [ ] **Step 3: Test clean-host installation**

Use the Ansible role on `192.168.101.56`; verify an enrollment event arrives,
durable identity/credential exists, the claim is removed, and Gateway WSS is
active.
