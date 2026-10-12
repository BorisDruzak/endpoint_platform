# Endpoint main integration — 2026-10-13

Scope: the operator approved current Task13, device-module-catalog-v1, browser
login and documentation for publication to main. Old experimental branches,
deployment and another seq04 attempt are excluded.

Original main: `9144a26472239e5a4c61a79aacdabbda4ec961bc`.
Integrated source tips:

- Task13: `4587950da8f70c100eb24e772f62a095abf2cb0b`.
- Device catalog: `8472d94f897c48041b718dafb84924b6cb73b86a`.

Both tips and original main are ancestors of the integration. The source diff
contains only approved paths. The newer 3.2.82 specification already on main was
retained instead of overwriting it with an older untracked copy.

## Integration commits and files

| Commit | Message | Included files |
| --- | --- | --- |
| `848b18e3054db7b0d89a92548dccd59b5bb60a8f` | chore(merge): integrate Task13 recovery protocols | 99 Task13 source, test and documentation files; explicit private-input gates for historical tests |
| `20425425e92e3fc6d2fc792fe242529d49c0d07c` | feat(modules): integrate device-scoped published catalog | 16 catalog service, contract, credential CLI, console, test and documentation files |
| `90087a866a99f10d0f155b6d44af7d081917c8f0` | fix(auth): redirect unauthenticated console pages to login | endpoint_server/main.py; tests/server/test_console_foundation.py |
| `7a1f000c3d749a5adc5b4c4331a233ce2ce90401` | test(canary): require private inputs for retained admission audit | tests/tools/test_task13_continuation_authorized_execution.py |
| `fbb32d1aff7714206319772d42d1903e16887007` | docs(canary): record bounded RuntimeException investigation | RCA plan and read-only investigation report dated 2026-10-12 |
| `a8ba02c62298874fe57f903fc45c10d2fd4e2385` | test(canary): gate native recovery fixtures on Windows | additive recovery, authorized execution and natural permission tests |

Test gates select native Windows or explicitly configured private inputs. No
runtime guard, assertion, claim rule or protocol source was changed by them.
Pure validation and consent tests remain enabled outside Windows.

## Verification

Python 3.12.14 on Windows; the existing test interpreter was reused.

- `python -B -m pytest tests pc_agent/tests -q --tb=short -o faulthandler_timeout=120`:
  **3843 passed, 327 skipped, 42 failed**, 401.09 seconds. Every failure reached
  unavailable POSIX `os.fchmod` in unchanged credential, ALT update or enrollment
  code. The same exact 42 failing node IDs were rerun on original main:
  **42 failed**, 2.71 seconds. Corresponding source and test files have no diff.
  This full Windows run is not a PASS.
- Final `python -B -m pytest tests/tools/test_task13*.py -q --tb=short`
  (PowerShell expanded the file list; private historical input unset):
  **359 passed, 157 skipped**, 46.75 seconds.
- `python -B -m pytest tests/contracts tests/server/test_device_module_catalog.py tests/server/test_helpdesk_diagnostic_credential.py tests/server/test_console_modules.py tests/operations/test_read_only_capability_projection.py tests/operations/test_network_capability_projection.py tests/operations/test_capability_platform_v2_gates.py -q --tb=short`:
  **460 passed, 1 skipped**. The skipped credential-file check requires POSIX.
- Login and affected historical test configuration:
  `python -B -m pytest tests/server/test_console_foundation.py tests/tools/test_task13_continuation_authorized_execution.py tests/tools/test_task13_continuation_readonly_recovery.py -q --tb=short`:
  **11 passed, 18 skipped**.
- `python -B tools/contracts/generate_contract_artifacts.py --check`: PASS.
- `python -m compileall -q endpoint_contracts endpoint_server pc_agent tools/canary/task13_continuation`: PASS.
- Cumulative `git diff origin/main...HEAD --check`: PASS.

The earlier explicitly configured live historical run had 506 PASS and 10
FAIL. Its failures reflected consumed recovery slots and a superseded operator
request. Those historical phase assertions were not changed or relabeled PASS.

Independent source/scope review passed for Task13, all catalog files, login,
RCA documentation, private-input test gates and the final native fixture gates.
Both required branches are included, excluded experiments are absent, and the
review found no credential material. GitNexus committed context was consulted;
dynamic route registration and the new canonical OpenAPI were verified in source
and tests. No consumer repository was edited.

Linux CI and installed runtime acceptance remain separate verification. A
read-only availability probe of the dedicated Linux test host timed out; no
remote changes were made. The Ubuntu CI fixture correction received source
review and Windows regression coverage, not a claimed Linux execution PASS.

## Preserved execution boundary

All five consumed claims and immutable historical evidence remain preserved.
Original plan, seal, deadlines, receipts, guest Facts, baseline and snapshot
were not modified. No new claim, seq04 dispatch, marker, restore, deployment,
MSI/Setup invocation or Agent runtime change occurred during integration.

The exact historical RuntimeException cause remains UNPROVEN. The current
enrollment identity SDDL string differs from the baseline; semantic permission
differences, writer/timing and historical causality are not established. No RCA
fix or accepted receipt04/RootCompletion is claimed by this publication.
