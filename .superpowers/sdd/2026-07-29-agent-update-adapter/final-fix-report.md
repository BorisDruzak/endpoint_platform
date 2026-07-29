# Agent Update Adapter Final Fix Report

Date: 2026-07-29
Branch: `codex/agent-update-adapter`
Implementation commit: `0afcf7904326072f33cfa3af39e4091f4a2ce514`

## Scope

This fix wave stayed local to the Endpoint Platform worktree. It did not
contact a remote host, run a canary, build or upload an artifact, deploy,
push, change a release version, or change launcher source.

## RED evidence

### Initial focused review findings

Command:

```powershell
python -m pytest pc_agent/tests/test_update_adapter.py::test_primary_200_payload_error_fails_closed_without_legacy pc_agent/tests/test_update_adapter.py::test_scheduled_handoff_ack_is_durable_across_adapter_restart pc_agent/tests/test_self_update_runtime.py::test_endpoint_download_mode_omits_device_bearer_and_token_trace pc_agent/tests/test_self_update_runtime.py::test_legacy_download_mode_keeps_device_bearer_without_logging_prefix pc_agent/tests/test_self_update_runtime.py::test_endpoint_schedule_uses_safe_no_auth_diagnostics pc_agent/tests/test_self_update_runtime.py::test_endpoint_scheduled_ack_failure_does_not_strand_local_handoff pc_agent/tests/test_self_update_runtime.py::test_sent_update_confirmation_waits_for_matching_handshake_ack pc_agent/tests/test_self_update_runtime.py::test_launcher_crash_history_without_operation_id_uses_safe_endpoint_state pc_agent/tests/test_self_update_runtime.py::test_rolled_back_report_uses_persisted_rollback_version pc_agent/tests/test_self_update_runtime.py::test_canary_config_selects_canary_recommendation_query pc_agent/tests/test_self_update_runtime.py::test_payload_error_returns_safe_status_without_legacy_or_raise pc_agent/tests/test_self_update_runtime.py::test_malformed_endpoint_contract_never_schedules_or_persists_pending -q
```

Expected result:

```text
FFF.FFFFFFF. [100%]
10 failed, 2 passed in 1.66s
```

The failures were the intended missing behaviors:

- `ClientPayloadError` escaped both adapter and status caller.
- durable scheduled-handoff methods did not exist;
- the downloader had no explicit `auth_mode="none"`;
- the endpoint scheduler did not request no-auth/safe-diagnostic mode;
- failed scheduled acknowledgement still raised after local handoff;
- sent handshake confirmation was not ACK-correlated;
- launcher history without `operation_id` was ignored;
- rollback reported the assigned rather than rollback version;
- the request remained hardcoded to `channel=stable`.

The two passing controls were the unchanged legacy bearer behavior and the
real WSAgent malformed-contract no-schedule path.

### Endpoint-correlated raw launcher diagnostic

Command:

```powershell
python -m pytest pc_agent/tests/test_self_update_runtime.py::test_endpoint_correlated_history_omits_raw_launcher_message -q
```

Expected result:

```text
FAILED ... AssertionError: assert 'failed_update_message' not in confirmation
1 failed in 0.84s
```

### Send-without-ACK integration boundary

Command:

```powershell
python -m pytest pc_agent/tests/test_self_update_runtime.py::test_sent_update_confirmation_waits_for_matching_handshake_ack -q
```

Expected first result after moving the assertion to the actual send helper:

```text
AttributeError: 'WSAgent' object has no attribute '_send_handshake_with_update_confirmation'
1 failed in 0.83s
```

### ACK must be processed before terminal delivery

Command:

```powershell
python -m pytest pc_agent/tests/test_self_update_runtime.py::test_sent_update_confirmation_waits_for_matching_handshake_ack -q
```

Expected result after adding the send helper but before moving delivery to the
end of ACK processing:

```text
AssertionError:
['scheduled', 'applied', 'ack_processed']
!=
['ack_processed', 'scheduled', 'applied']
1 failed in 0.86s
```

## Changed files

- `pc_agent/update_adapter.py`
  - fail-closed post-response aiohttp handling;
  - atomic safe `endpoint_update_state.json`;
  - durable scheduled acknowledgement record/retry;
  - safe handoff state loader.
- `pc_agent/ws_agent.py`
  - explicit configured channel selection;
  - strict primary scheduling with no artifact-host bearer and safe traces;
  - durable scheduled retry integration;
  - launcher history correlation;
  - matching processed handshake ACK gate for terminal reporting;
  - rollback-version reporting;
  - removal of handshake bearer-prefix logging.
- `pc_agent/core/orchestrator.py`
  - explicit `device|none` update-download auth mode;
  - unchanged default legacy device authorization;
  - Endpoint-safe trace/error mode;
  - no update-download bearer-prefix log.
- `pc_agent/config/config_loader.py`
  - validated `server.update_channel: stable|canary`.
- `pc_agent/config/settings.default.yaml`
- `pc_agent/config/settings.yaml`
  - documented/defaulted update channel.
- `pc_agent/tests/test_update_adapter.py`
  - payload-read fail-close and durable restart retry coverage;
  - removed the vacuous pending-file assertion.
- `pc_agent/tests/test_self_update_runtime.py`
  - real scheduling/header/trace, handshake, retry ordering, correlation,
    canary query, safe status, and malformed-contract integration coverage.
- `pc_agent/docs/SELF_UPDATE.md`
- `pc_agent/docs/AGENT_UPDATE_WORKFLOW.md`
- `pc_agent/docs/CODEMAP.md`
  - corrected diagnostic scope, channel selection, durable retry, terminal
    ordering, and legacy POST wording.

## Finding-by-finding mapping

1. **No bearer to arbitrary artifact host / no bearer prefix**
   - Strict primary scheduling calls `_handle_update(...,
     download_auth_mode="none", safe_diagnostics=True)`.
   - `_download_file_to_path()` defaults to `device`, preserving legacy
     Authorization behavior, but accepts only the explicit internal modes
     `device` and `none`.
   - Strict mode sends `{}` headers to the artifact host.
   - Update-download and handshake logs no longer include bearer prefixes.
   - Tests assert strict empty headers, legacy Authorization preservation,
     and absence of token/prefix text.

2. **`applied` only after matching handshake ACK**
   - `_send_handshake_with_update_confirmation()` only sends and stages the
     confirmation.
   - `handle_message()` compares the `handshake_ack.request_id`, processes
     normal ACK state first, and only then delivers the staged terminal result.
   - Tests cover send without ACK, mismatched ACK, matching ACK, and processed
     ACK ordering.

3. **Durable/recoverable `scheduled`**
   - `requested` remains a required successful acknowledgement before
     scheduling.
   - Only a successful existing local schedule creates the safe durable
     handoff record and attempts `scheduled`.
   - Non-204/lost delivery no longer turns a successful local handoff into an
     exception; `scheduled_ack_delivered_at` remains null.
   - The restarted agent retries `scheduled` from
     `endpoint_update_state.json` before terminal report delivery.
   - Tests prove persistence, restart retry, and
     `scheduled -> applied` terminal ordering.

4. **Launcher history without `operation_id`**
   - The safe state stores only operation id, assigned version, rollback
     version, and scheduled-delivery timestamp.
   - Launcher failure/crash records without `operation_id` correlate by the
     validated assigned version; rollback correlation also checks the launcher
     rollback/previous version when present.
   - `failed` reports the assigned version with
     `launcher_apply_failed`; `rolled_back` reports the rollback version with
     `launcher_rolled_back`.
   - Endpoint-correlated history does not forward the raw launcher message.
   - Focused tests cover failed and rolled-back correlation plus report body.

5. **Stable and canary selection**
   - `ServerConfig.update_channel` is a Pydantic literal restricted to
     `stable|canary`, default `stable`.
   - The WSAgent request uses this setting and safely falls back to `stable`
     for non-model test/compatibility objects.
   - A focused test asserts the exact canary recommendation query.

6. **All post-response aiohttp read errors fail closed**
   - `fetch_recommendation()` catches all `aiohttp.ClientError` and timeouts.
   - Legacy fallback remains only 404/501 and pre-response connection/timeout.
   - Any post-response error, including `ClientPayloadError`, returns the safe
     endpoint-unavailable result without raising or polling legacy.
   - Adapter and WSAgent status-caller tests cover this.

7. **Documentation corrections**
   - Safe diagnostic claims now apply only to new Endpoint-specific values and
     explicitly exclude legacy scheduler/launcher local path traces.
   - Startup documentation now says strict Endpoint assignments schedule
     locally; only eligible fallback uses the legacy device update POST.
   - Channel config, durable state, scheduled retry, and matching ACK terminal
     semantics are documented in SELF_UPDATE, workflow, and CODEMAP.

8. **Vacuous malformed-contract pending assertion**
   - Removed the adapter-unit `tmp_path.rglob("pending_update.json")` assertion.
   - Added a WSAgent integration test with a real malformed endpoint response,
     a scheduler double that fails if called, and an assertion that no pending
     update is persisted.

## GREEN and verification evidence

Focused regression suite:

```powershell
python -m pytest pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py -q
```

```text
55 passed in 0.91s
```

Server consumer compatibility:

```powershell
python -m pytest tests/server/test_update_agent_api.py -q
```

```text
7 passed, 357 deprecation warnings in 1.62s
```

Full available non-manual agent suite:

```powershell
python -m pytest pc_agent/tests -m "not manual" --ignore=pc_agent/tests/test_remote_assist_runtime_module_package.py --ignore=pc_agent/tests/test_support_module_packages.py -q
```

```text
509 passed, 4 deselected, 9 warnings in 42.40s
```

Static/syntax checks:

```powershell
python -m ruff check --select E9,F63,F7,F82 pc_agent/update_adapter.py pc_agent/ws_agent.py pc_agent/core/orchestrator.py pc_agent/config/config_loader.py pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py
python -m compileall -q pc_agent/update_adapter.py pc_agent/ws_agent.py pc_agent/core/orchestrator.py pc_agent/config/config_loader.py pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py
git diff --check
```

```text
All checks passed!
compileall exit 0
git diff --check exit 0
```

Attempted unfiltered agent suite:

```powershell
python -m pytest pc_agent/tests -m "not manual" -q
```

```text
2 collection errors:
ModuleNotFoundError: scripts.build_module_zip
ModuleNotFoundError: scripts.register_support_modules
4 deselected, 2 errors in 1.65s
```

## Residual concerns

- The worktree does not contain the repository `scripts/` modules required by
  two unrelated package tests, so the unfiltered agent suite cannot collect.
  The full remaining non-manual suite passed with exactly those two files
  ignored.
- Existing Python 3.14 deprecation warnings remain in FastAPI/Starlette and
  GUI event-loop test paths.
- Full-rule Ruff still reports pre-existing style/unused-import findings in
  the large legacy `ws_agent.py` and `orchestrator.py`; syntax-critical Ruff,
  compileall, and diff checks pass.
- Live launcher/canary behavior was intentionally not exercised because this
  task prohibited remote hosts, canary, artifacts, deploys, and launcher
  changes.

## Final mechanical formatting verification

Ruff formatting was applied to exactly the three files identified by final
verification:

```powershell
python -m ruff format pc_agent/config/config_loader.py pc_agent/core/orchestrator.py pc_agent/tests/test_self_update_runtime.py
```

```text
3 files reformatted
```

The resulting formatting and focused adapter/runtime behavior were verified:

```powershell
python -m ruff format --check pc_agent/config/config_loader.py pc_agent/core/orchestrator.py pc_agent/tests/test_self_update_runtime.py
python -m pytest pc_agent/tests/test_update_adapter.py pc_agent/tests/test_self_update_runtime.py -q
git diff --check
```

```text
3 files already formatted
.......................................................                  [100%]
55 passed in 1.19s
git diff --check exit 0
```

The format-only commit is:

```text
e6308cb pc_agent: normalize update adapter formatting
```
