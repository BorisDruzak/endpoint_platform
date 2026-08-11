# Canonical ALT RPM First-Boot Enrollment Design

## Goal

Allow the canonical frozen core in `endpoint-agent-3.2.14-alt1` to exchange a
one-time systemd claim for a durable credential before it starts the ordinary
Gateway runtime.

## Root cause

The RPM launcher selects the PyInstaller core built from `pc_agent/runtime/main.py`.
That entrypoint currently starts `run_runtime()` directly, which requires the
durable `device-credential`.  The older claim exchange lives in `ws_agent.py`,
which is intentionally excluded from the frozen core.  A first install therefore
returns `75` before any `/agent/v1/enroll` request.

## Decision

`runtime.main` will recognize the existing
`ENDPOINT_AGENT_ENROLLMENT_REQUIRED=1` service contract. Before starting the
ordinary runtime it will resolve only the fixed systemd credential paths and
call `run_linux_enrollment_gate`. `enrolled`, `already_enrolled`, and
`handoff_pending` continue to Gateway WSS; the latter already has a verified
durable credential and awaits only root-side claim-source removal. Every other
enrollment outcome returns `75` without starting ordinary device-credential
transport.

The behavior reuses `linux_enrollment_runtime` and `enrollment_bootstrap`; it
does not add another HTTP client, claim parser, or alternate credential path.

## Verification

The regression test invokes `runtime.main` with the first-boot environment,
mocks only the existing enrollment boundary, and asserts that a successful
enrollment reaches `run_runtime`.  It must fail on the current code because
the gate is not called.  Focused runtime tests, the packaging tests, a rebuilt
RPM, and a clean-host install prove the complete path.
