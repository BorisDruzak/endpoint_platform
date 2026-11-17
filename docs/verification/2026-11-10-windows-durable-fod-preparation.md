# Durable Windows FoD completion preparation

This is source/test evidence, not a release or fleet acceptance. Windows primary
remains177, Linux primary183. Policy16 remains paused on187/all_active/max2.
The [188 incident](2026-11-10-windows188-fleet-auto.md) retains original native,
servicing and firewall evidence. No189 installer has been built or published.

## Corrected source behavior

Commit `c47869338478ead22a30adef9c5b371b02508f1b`,
`fix(windows): preserve durable FoD completion after caller loss`, introduces
schema2 operation-bound preparation and durable protected baseline/completion.
Baseline precedes any firewall reservation or Add; completion binds its bytes by
SHA256 and the exact request/operation/nonce. The exclusive worker lock spans
cleanup and final atomic publication. Re-entry adopts only that exact complete
proof and rechecks capability/signature state, without another Add.

The fixed native PowerShell worker starts suspended, must be outside every
caller Job before resume, inherits no handles/pipes and has no killing timeout.
The outer staged Support installer likewise waits without its old660second kill.
Read-only queries retain finite timeouts. Existing observer108 remains immutable;
its40minute observation bound already keeps waiting rather than killing Setup.

Missing/partial/malformed/mismatched proof, caller loss before launch and legacy
v1 unknown all retain recovery holds. A foreign global sshd while Server FoD is
missing refuses preparation before mutation. A replaced firewall reservation
still reports conflict; no new rule ownership or normalization is inferred.
Old independent Support remains selected until ordinary verified activation.

The uninstall gate verifies idle v2 proof before destructive component cleanup
and retains operation evidence. Rollback-image creation is deferred until apply,
with an active-image hash recheck before stopping/replacing it. This permits
durable-proof adoption after a caller lost during dependency preparation, while
pre-existing unknown `.previous` artifacts retain their original strict hold.

Files in this atomic commit:

- `pc_agent/platform/windows/provision.py`
- `pc_agent/platform/windows/support_access.py`
- `pc_agent/platform/windows/support_access_native.py`
- `pc_agent/platform/windows/support_access_os.py`
- `pc_agent/tests/windows/test_support_access_os.py`
- `pc_agent/tests/windows/test_support_fod_powershell51.py`
- `pc_agent/tests/windows/test_support_setup_lifecycle.py`

## Verification

Python3.12.14/pywin32311 on Windows, using the existing test environment:

```
C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe -m pytest pc_agent/tests/windows/test_support_access_os.py pc_agent/tests/windows/test_support_fod_powershell51.py pc_agent/tests/windows/test_support_setup_lifecycle.py pc_agent/tests/windows/test_support_os_runtime.py pc_agent/tests/windows/test_support_optional_origin.py pc_agent/tests/windows/test_support_access.py pc_agent/tests/windows/test_support_access_bundle.py -q
```

193 passed,3 skipped in14.02seconds. Full Windows suite:

```
C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe -m pytest pc_agent/tests/windows -q
```

2641 passed,4 skipped in206.44seconds. Both runs include one intentional existing
duplicate ZIP-member warning from the malicious-archive rejection fixture.
No process/handle warning. `git diff --check` passed before and after staging.

RED/GREEN includes failed adoption/proof tests before implementation, foreign
service rejection before Add, deferred rollback backup and changed-image guards.
Actual isolated WindowsPS5.1 executes the production transaction with every native
capability/service/firewall command replaced before AST-checked execution. Real
nested kill-on-close Job fixtures terminate the caller during fake Add; the
independent worker survives, publishes cleanup/completion and permits re-entry
without a second Add. Restrictive Jobs refuse before baseline/Add. No test
installed a real capability or changed operator services/firewall.

Context7 primary pywin32 documentation was consulted; no exact311 CreateProcess
example was returned. Actual pinned native fixtures and existing caller-chain
source supplied behavioral validation. GitNexus was unavailable in enabled tools;
no manual index/group synchronization was attempted.

Independent task review: spec-compliance PASS, code-quality PASS, no actionable
findings. The reviewer checked the exact seven-file range and the concrete
receipt/lock/protection/activation/uninstall risks; it did not rerun the suites
or treat this as release qualification.

## Decisions and costs

- Keep the existing activation mutex and add a distinct worker lock for orphan
  completion. An unresolved worker blocks adoption/uninstall; the cost is a
  recovery hold instead of attempting another Add.
- Delay the rollback copy until activation, then recheck the old image. This
  permits post-FoD caller recovery; an error here would affect compensation, so
  existing compensation tests and new changed-image checks were retained.
- Accept only exact v2 durable completion. Legacy v1 unknown stays held even
  after Windows files appear; the cost is explicit manual recovery on ADMIN-2.
- Preserve the foreign sshd on MUNSLU-S2 and refuse missing-Server preparation.
  This delays its native Support migration but preserves its working SSH.
- Keep rollout paused while rule normalization and a real missing-FoD test await
  the user's decision. This delays automatic delivery to offline PCs and avoids
  treating partial native acceptance as complete Support acceptance.

## Live limits and remaining decisions

Actual188 on ADMIN-2 is APPLIED/native0/191.404seconds/sensor1, but Support stays
1.0.1 and the original v1 servicing receipt remains held. Authoritative exact CBS
session finalized S_OK; this does not reconstruct the lost helper cleanup proof.
At2026-11-10T00:18:18.965678Z actual strict UUID-pinned administrator SSH still
worked through old Support PID28388. Global OS sshd was Stopped/Manual/PID0 and
port22 had no listener. Original348byte servicing receipt SHA256
`276fc632df958e9c9d83c7822bca22455ced84c7edd6ed4831185e06259224ce` and complete
104951137byte CBS log SHA256
`af5db1d1f72837ae993aa03e68cece0b6705e83db121211dac7a7a205e43ad9f` were copied
off the live state and verified byte-for-byte. Neither live source was changed.

Untouched177 MUNSLU-S2 has Client Installed/Server NotPresent and a running Auto
global sshd at ProgramFiles/OpenSSH. Its strict administrative preflight was
read-only; it is unsuitable as a pristine missing-FoD canary. Its existing
service/process, identity, keys and original pending177 lifecycle fact were kept.

Two user decisions remain pending: authorize disabling the exact new standard
Windows port22 rule when it did not exist before this component installation;
and authorize temporary removal/reinstallation of only OpenSSH Server on test120
for a fresh installation trial. No permission is inferred from a preselected
answer or elapsed time. No dependent rule mutation or OS removal has occurred.
The current AGENTS.md rule forbids manufacturing an unattended source canary by
manual OS preparation; an explicitly authorized fault test must be labelled as
such and cannot silently substitute for untouched-source qualification.

Normal offline auto-update needs no SSH lease: after a qualified persistent policy
is enabled, fresh matching WSS/Setup readiness and a supported qualified source
permit dynamic admission on reconnect. Qualification expiry and recovery/busy
holds still apply. Policy16 is currently paused, so no new automatic assignments
are being created. No189 live qualification, download promotion or resumed fleet
acceptance is claimed by these source tests.
