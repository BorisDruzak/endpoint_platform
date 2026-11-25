# Task 6 Linux182 loginctl property selection fix

## Scope and cause

Parent supplied actual ALT11.4/systemd258.9 evidence: `loginctl show-session 6 --no-pager --property=Active,Remote,Class,Type,User,State,TimestampMonotonic,Leader` exits 0 with empty stdout. Repeated `--property NAME` arguments return all eight properties. An empty property mapping becomes `session_prerequisite_absent`, preventing the durable owned-sensor stop receipt and leaving the prior sensor alive through native removal. This report does not claim the legacy181 remainder was recovered.

`session_context` now requests each of the same eight properties using repeated `--property NAME` arguments. The only other direct loginctl call in this module is `list-sessions`, which has no property selection and needs no change. The systemctl property selection is a separate CLI and was deliberately not changed.

The regression runs the real session discovery, context construction, handoff, receipt persistence, retained preparation check, and resume decision. Its external command fake implements literal loginctl property selection: a comma-joined name matches no property and returns empty bytes, while repeated flags return the selected fields. The stop produces `stopped_owned` and a durable receipt containing all eight session properties; retained-only resume consumes that same receipt and preserves disabled boot policy. Windows-only POSIX account/runtime/environment boundaries are fixture substitutes; this test is not real administrator SSH or native OS ownership proof.

## RED

Before changing production code:

```powershell
& 'C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe' -m pytest -q pc_agent/tests/test_linux_installation_user_sessions.py::test_loginctl_property_selection_allows_owned_stop_and_same_session_resume
```

Exit 1: **1 failed in 0.48s**. Exact expected mismatch at the first stop result: actual `{'session':'6','status':'session_prerequisite_absent'}` versus expected `{'session':'6','uid':1000,'status':'stopped_owned'}`. This reproduced the supplied live failure without a missing import or fixture error.

## GREEN and verification

```powershell
& 'C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe' -m pytest -q pc_agent/tests/test_linux_installation_user_sessions.py pc_agent/tests/test_linux_installation_coordinator.py pc_agent/tests/test_linux_installation_lifecycle.py pc_agent/tests/test_linux_installation_notification.py tests/native/test_linux_installation_native.py -rs
```

Exit 0: **45 passed, 10 skipped in 1.10s**. All ten native-file tests explicitly skipped with `requires explicitly owned isolated Linux native harness`; Windows has neither POSIX semantics nor that opt-in owned harness. Existing session change, environment change, foreign/masked/disabled unit, timestamp/receipt and unresolved-stop protections passed in the focused portable suite. POSIX unsafe filesystem cases remain unverified here and must be exercised by the parent on ALT. No broad/global suite was run, per the explicit task boundary.

`git diff --check` passed before commit. Complete task diff and status were inspected. The workspace has no `scripts/verify_workspace.py`. The pc_agent AGENTS references to `.agents/skills/pc-client-systematic-debug`, `.agents/skills/pc-client-docs-drift` and routing documents are absent; available Superpowers TDD, systematic debugging and verification guidance were consulted instead. GitNexus tools were unavailable per parent discovery. Context7 resolved systemd and was queried against v257.13 (closest available prior version to actual258.9); its returned snippets did not document loginctl selection, so no documentation claim was substituted for the supplied exact live command evidence.

## Files

- `pc_agent/platform/linux/installation_user_sessions.py`
- `pc_agent/tests/test_linux_installation_user_sessions.py`
- `.superpowers/sdd/2026-11-07-linux-support-lifecycle/task6-linux182-loginctl-fix-report.md`

No Gateway or server protocol changes, version bump, signing, VM operation, deployment, or release/ledger edit. No new runtime component or entrypoint; this report documents the corrected invocation, and CODEMAP need not change for the same session handoff architecture.

## Retained limits

Exact owned fragment, loaded unit, absent drop-ins, masked/disabled policy, active genuine session, safe runtime/environment, unchanged configuration, and durable exact stop/restore receipt guards are unchanged. No process-name killing, unit enabling, identity replacement, unknown-native replay, or relaxation for a not-found-but-active legacy unit is introduced. The parent owns bounded legacy181 recovery and actual Linux182 CLI/native acceptance after restoring its isolated SDK. Windows GREEN alone does not establish fresh accepted user telemetry or qualify a native release.
