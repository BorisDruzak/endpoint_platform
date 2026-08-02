# Task 11 — Windows service and provisioning contract report

## Status

Implemented the remaining Task 11 Windows contract in the isolated
`codex/headless-agent-runtime` worktree. The implementation preserves the
already-approved persisted server-issued `Device.id` by writing and rereading
the existing canonical `enrollment-identity.json`; it does not use or derive
a legacy machine identity.

No real Windows service, MSI registration, deployment, production host, or
test host was accessed or modified.

## Design decisions

- `pc_agent/platform/windows/service.py` is a small, headless LocalService
  boundary. `ServiceCoordinator` accepts an injected SCM status adapter and
  an async neutral-runtime callable. It maps start, stop, shutdown, update
  exit, and normal completion into service-state transitions without adding a
  new Gateway loop. The neutral runtime remains responsible for reconnects
  and controlled update exit `42`.
- The pywin32 imports are inside `run_windows_service()` and the real SCM
  start adapter. Importing Windows contract modules on non-Windows therefore
  does not require pywin32 or reach Qt/UI/Desktop modules.
- `pc_agent/runtime/main.py` exposes the required mutually-exclusive modes:
  `--windows-service`, `--verify`, and `--print-safe-status`. Safe status can
  report an invalid configuration even when a CA was not supplied; it returns
  only readiness facts and never a bearer or claim.
- `pc_agent/platform/windows/acl.py` defines explicit DACL policy for
  `SYSTEM`, `Administrators`, `NT SERVICE\EndpointAgent`, and
  `NT SERVICE\EndpointAgentUpdater`. The permanent credential is readable by
  the agent service only; the updater has write-only replacement access and
  ordinary users receive no read entry.
- `pc_agent/platform/windows/provision.py` has injected enrollment, ACL, and
  service adapters. It reads one-time material only from stdin or a protected
  file; its argparse surface has no claim/token property. It validates the
  absolute HTTPS origin and local CA, protects the directory, atomically
  stages the claim, atomically persists bearer plus canonical identity, proves
  both through their existing readers, starts the service, and only then
  deletes the staged claim. Exceptions return a generic failure from the CLI,
  without writing material to stdout.

## TDD evidence

### RED 1 — new Windows contract surface

After creating the service/provisioning tests and before adding the production
modules, ran:

```powershell
python -m pytest pc_agent/tests/windows/test_service_contract.py pc_agent/tests/windows/test_provisioning_contract.py -q
```

Result: `11 failed`. Every failure was the expected
`ModuleNotFoundError: No module named 'pc_agent.platform.windows.service'` or
`.provision`, demonstrating the desired service/provisioning public boundary
did not yet exist.

### GREEN 1 — implemented boundary

After adding the platform modules, adapters, and tests, ran the same command.

Result: `11 passed in 0.57s`.

### RED 2 / GREEN 2 — executable modes

Added the exact mode test and ran:

```powershell
python -m pytest pc_agent/tests/windows/test_service_contract.py::test_headless_entrypoint_exposes_exact_windows_service_modes pc_agent/tests/windows/test_provisioning_contract.py::test_windows_acl_contract_keeps_ordinary_users_off_the_credential -q
```

Result: one expected failure: `--windows-service` was unrecognized by
`pc_agent.runtime.main` (`SystemExit: 2`). After adding the mutually-exclusive
mode flags and lazy dispatch, the focused suite passed.

### RED 3 / GREEN 3 — valid Windows enrollment request

Ran:

```powershell
python -m pytest pc_agent/tests/windows/test_provisioning_contract.py::test_https_windows_enrollment_sends_a_valid_windows_contract_request -q
```

Result before the fix: expected Pydantic failure because
`AgentEnrollmentRequestV1.requested_at` was absent. Added UTC
`requested_at`; result after the fix: `1 passed in 0.50s`.

### RED 4 / GREEN 4 — safe status with missing CA

Ran:

```powershell
python -m pytest pc_agent/tests/windows/test_service_contract.py::test_safe_status_mode_reports_invalid_setup_without_requiring_a_ca_argument -q
```

Result before the fix: expected assertion failure, `75 != 0`, because
`main()` returned before emitting safe status. Allowed only the
`--print-safe-status` mode past the CA-presence gate; result after the fix:
`1 passed in 0.49s`.

## Final verification

```powershell
python -m pytest pc_agent/tests/windows pc_agent/tests/runtime/test_headless_imports.py pc_agent/tests/runtime/test_headless_verify.py pc_agent/tests/runtime/test_headless_lifecycle.py -q
```

Result: `52 passed in 0.91s`.

```powershell
Get-ChildItem 'pc_agent\platform\windows' -Filter '*.py' | ForEach-Object { python -m py_compile $_.FullName }; python -m py_compile 'pc_agent\runtime\main.py'; git diff --check
```

Result: exit `0`; Python compilation succeeded and `git diff --check` found
no whitespace errors. Git emitted only the existing CRLF conversion warnings
for two tracked files.

The repository instruction suggested `python scripts/verify_workspace.py`.
That command was attempted, but this isolated worktree has no
`scripts/verify_workspace.py` file, so Python exited `1` before executing a
workspace check. The targeted suite and compilation checks above did run.

The broader requested agent baseline was also attempted:

```powershell
python -m pytest pc_agent/tests -m "not manual" -q
```

It stopped during collection with two pre-existing repository-layout imports:
`scripts.build_module_zip` and `scripts.register_support_modules` do not exist
in this worktree. This is unrelated to the Windows contract files; the focused
Windows and neutral-runtime suites completed successfully.

## Documentation

- Added `docs/agent/WINDOWS_RUNTIME_DESIGN.md` for the service, ACL,
  provisioning, secret-output, and deferred-MSI boundary.
- Updated `pc_agent/docs/CODEMAP.md` because this task adds a runtime
  entrypoint contract and platform module structure.

## Self-review

- Service tests use an injected SCM adapter and cover start, stop, shutdown,
  controlled update exit, retained Gateway reconnect behavior, and forbidden
  desktop/UI imports.
- Provisioning tests cover HTTPS-origin validation, missing CA rejection,
  protected directory/credential adapters, atomic durable-state flow,
  permanent credential proof before claim deletion, service start ordering,
  protected-file input, and no token output.
- The source and `--print-safe-status` output contain no raw claim, bearer,
  or enrollment response serialization.
- The package imports without pywin32 on this Windows-independent test path;
  pywin32 calls remain execution-time boundaries.

## Limitations / follow-up

- The contract does not build an `endpoint-agent-provision.exe` artifact or
  MSI tables; the later Windows MSI task must bind this `main()` to that
  executable and install `EndpointAgent` as LocalService.
- DACL application uses pywin32 and was unit-tested through injected adapters;
  its exact virtual-account resolution and installed-service behavior need a
  disposable Windows VM/MSI pilot.
- No live Gateway enrollment occurs in these tests. The HTTPS enrollment client
  sends the existing typed Endpoint request, while tests substitute the
  network boundary and retain no secret output.

## Review fix round 1 (2026-08-02)

### Root cause and changes

- SCM `SvcStop`/`SvcShutdown` may execute on a callback thread. The original
  coordinator called `Task.cancel()` there directly and had no stop-before-task
  latch. The coordinator now records the owning asyncio loop, uses
  `call_soon_threadsafe()` to cancel only from that loop, and returns cleanly
  without starting a runtime when a stop was latched during startup.
- The directory DACL now uses object/container inheritance ACE flags, and the
  provisioner explicitly protects the atomically staged claim as well as the
  permanent credential. Protected-file input rejects symlink/reparse sources
  and the pywin32 adapter inspects rather than rewrites its DACL.
- The pywin32 stopped-status helper reports update exit `42` as a Win32
  service-specific error (`ERROR_SERVICE_SPECIFIC_ERROR`, `svcExitCode=42`)
  rather than silently reporting zero.
- Endpoint origin validation now accesses parsed hostname/port defensively and
  rejects invalid ports or empty hosts. CA validation requires a nonempty,
  parseable TLS CA file before an enrollment adapter can be called.
- Each atomic replacement flushes the containing directory metadata, and claim
  deletion flushes that directory before the provisioner returns.

### RED / GREEN evidence

```powershell
python -m pytest pc_agent/tests/windows/test_service_contract.py::test_service_stop_latched_before_runtime_task_prevents_start_race -q
```

RED result: expected failure because `runtime.start` occurred after a
pre-task shutdown request.

```powershell
python -m pytest pc_agent/tests/windows/test_provisioning_contract.py::test_provisioning_rejects_non_origin_https_endpoint pc_agent/tests/windows/test_provisioning_contract.py::test_provisioning_rejects_non_certificate_ca_content -q
```

RED result: three expected failures: `https://:`, an invalid port, and
arbitrary CA text were accepted.

```powershell
python -m pytest pc_agent/tests/windows -q
```

GREEN result: `22 passed in 1.21s` after the fixes. The worker-thread SCM test
uses an actual `threading.Thread` and asserts that cancellation completes
before its watchdog callback.

Final round verification:

```powershell
Get-ChildItem 'pc_agent\platform\windows' -Filter '*.py' | ForEach-Object { python -m py_compile $_.FullName }; python -m pytest pc_agent/tests/windows pc_agent/tests/runtime/test_headless_imports.py pc_agent/tests/runtime/test_headless_verify.py pc_agent/tests/runtime/test_headless_lifecycle.py -q; git diff --check
```

Result: `58 passed in 1.54s`; compilation and whitespace checks succeeded.

## Review fix round 2 (2026-08-02)

### RED / GREEN — strict endpoint host and localized ACL SID handling

Added malformed-host regression coverage for whitespace, underscore,
percent-escaped, leading-dot, and empty-label hosts, including a provisioner
test proving that none reaches the injected enrollment adapter. Added SID
coverage where the Administrators well-known SID is represented by a localized
account name and a Users SID remains rejected.

```powershell
python -m pytest pc_agent/tests/windows/test_provisioning_contract.py::test_malformed_origin_is_rejected_before_enrollment_adapter pc_agent/tests/windows/test_acl_sid_contract.py -q
```

RED result: five malformed hosts reached the enrollment adapter, and the ACL
SID helper import failed because inspection still depended on display names.

Implemented strict DNS-label or IP-literal validation (with bounded host/port
handling) and changed protected-file ACL comparison to canonical SID strings:
well-known LocalSystem and Builtin Administrators SID strings plus resolved
virtual-service SID strings. No localized display name participates in the
comparison.

```powershell
python -m pytest pc_agent/tests/windows/test_provisioning_contract.py::test_malformed_origin_is_rejected_before_enrollment_adapter pc_agent/tests/windows/test_provisioning_contract.py::test_provisioning_rejects_non_origin_https_endpoint pc_agent/tests/windows/test_acl_sid_contract.py -q
```

GREEN result: `16 passed in 0.55s`.

Round-2 final focused verification (Windows contract plus neutral runtime):
`69 passed in 1.56s`; platform modules compiled and `git diff --check` passed.
