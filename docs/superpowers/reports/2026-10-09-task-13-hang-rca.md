# Task 13 hang RCA and controlled recovery status

Date: 2026-10-09.
Investigated product baseline: `5d36fd383328cba10d2d3f6b55fe2e8489b8fb31`.
Resume decision: **BLOCKED**.

This public report summarizes a private forensic dossier. Exact commands, raw
logs, process identities, guest configuration and evidence byte anchors remain
in protected local storage. This report does not publish that material.

## Established findings

The failed operation was `compare-after-start-024` in the environment recovery
protocol. Its local transport expired after **119.906 seconds** with
`TimeoutError`, zero stdout and stderr, and no persisted exit code. Local stdin
submission/finalization was confirmed and the owned local SSH child was retired.
The acceptance adapter then rejected the incomplete transport before parsing
any comparator result. The outer `ValueError` represents that rejection; it is
not evidence of a native comparison mismatch.

Windows PowerShell Event ID 400 supplied HostApplication records for both
processes. Reconstructed command quoting matched the exact command hashes and
lengths recorded in the historical native/CIM observations:

| PID | Proven role | Command length |
|---|---|---:|
| 3976 | SSH PowerShell DefaultShell forwarder, using `-c` to invoke child PowerShell | 14,427 characters |
| 5228 | Child PowerShell running `-NoProfile -NonInteractive -EncodedCommand` | 14,407 characters |

Both encoded tokens match the same saved wrapper bytes. This resolves the
process roles; matching encoded tokens alone would not have resolved them.
The observed parent chain was 4212 → 3976 → 5228. The full identity of 4212 and
all descendants of 5228 were not retained, so a complete process tree is not
claimed.

The wrapper synchronously reads exactly 287,348 Base64 characters through
`Console.In.Read`, checks wire/body identities, decompresses and validates a
591,778-byte body, creates the sealed helper ScriptBlock and would invoke
`Step=compare`. That helper would read/hash the protected baseline and execute
payload, MSI/component, service and security checks before emitting its result.

Event ID 4104 proves a script block was recorded for PID 5228. It does not prove
packet-read completion, helper entry, a particular native call or the executing
instruction. **The remote blocking operation remains UNKNOWN.** No stack dump
or instruction-level trace was saved before process termination.

## Timeline and preserved checkpoint

All times below are UTC on 2026-10-09.

| Observation | Time |
|---|---|
| Compare transport dispatched | 06:48:26.123467 |
| Child 5228 PowerShell engine startup recorded | 06:48:28.3229815 |
| Child 5228 script block recorded | 06:48:28.4232572 |
| Compare timeout persisted | 06:50:26.025470 |
| Parent 3976 engine shutdown recorded near cleanup | 07:43:34.4874396 |
| Preserved baseline hash and absent marker reconfirmed | 08:37:17.4150097 |

Four complete recovery receipts and their chain were retained. The selected
disk-only snapshot and protected 2,561,556-byte baseline were preserved. A fresh
read-only query reconfirmed the original baseline hash and absent marker.
Rollback/restore has not passed in this run.

Guest processes survived the local timeout. Separately authorized cleanup
confirmed PID 5228 termination and exit through a retained handle. PID 3976 was
already absent at lookup. A separate read-only scan found no exact failed-wrapper
matches. Cleanup review PASS applies only to those bounded actions.

Previously reviewed hypervisor observations retained unchanged configuration,
generation, four name-keyed snapshot records and twelve logical-volume records.
Those provider/hypervisor facts were not refreshed by this investigation and
are not present-time resume authority.

## Installer, SCM, update transactions and logs

The read-only investigation verified the dedicated test VM identity and
unchanged boot. It did not invoke Setup, MSI or service operations.

| Boundary | Observed evidence | Limit |
|---|---|---|
| Windows Installer | `msiserver` Stopped/Manual; no `msiexec.exe`; checked InProgress, Rollback/Scripts and reboot-pending keys absent | Current point only; does not exclude a historical blocked read-only MSI API or prove absence of a kernel mutex owner |
| SCM | EndpointAgent Running/Auto; EndpointAgentUpdater Stopped/Manual | Historical wait and full installed ownership acceptance were not established |
| Installer fence | Fixed installer transaction file absent | Current point only |
| Update state | No pending update, startup attempt or terminal outcome; startup confirmation retained; 11 report entries, all delivered | Null projections of other history fields do not imply corrupt source records |
| Application/Python/MSI logs | 29 Application events in the UTC window; no selected MsiInstaller, Python, Application Error or WER records | Missing records do not exclude a native wait; no separate Python log tied to 5228 was found |
| System/SCM logs | 106 System events; six SCM records around shutdown/boot | Service names/details were not collected, so these are not assigned to Endpoint or treated as the hang cause |
| PowerShell logs | 283 classic and 129 operational events; child startup/script block and parent shutdown recorded | Generic `pipe` or `error` keywords can occur in script text and do not diagnose a wait |
| SSH logs | 30 OpenSSH operational events; DefaultShell confirmed as PowerShell | Historical stdin handles and session internals were not recorded |
| Endpoint logs | Install log predates the incident; command-completion log continues; update history predates this run | Historical install error keywords do not establish an incident MSI failure |

The final log query used UTC `SystemTime` XPath. An earlier DateTime-window
query and root-directory update-file projection were superseded. A first detail
collector failed on a shadowed PowerShell variable; its partial output/error was
preserved. Corrected collectors completed with exit 0 and zero stderr. These
collector corrections are not fixes for the Task 13 hang.

## Candidate causes and evidence limits

| Candidate | Disposition |
|---|---|
| SSH forwarding or synchronous exact-count stdin read | Plausible; forwarding roles proven, blocked read unproven |
| MSI transaction/component query | No transaction invocation in compare; read-only native queries exist, but entry into a blocking API is unproven |
| Installer fence/update mutex | No product mutation-lock acquisition path invoked by the helper; no mutex-wait evidence |
| Named-pipe RPC | Possible internal COM/MSI/SCM/SSH dependency; no wait-chain or stack evidence |
| SCM `WaitForStatus` | No explicit call in this wrapper/helper; SCM/CIM reads and `sc.exe sdshow` exist |
| Process completion | Parent/SSH may wait for child; helper may wait for its external `sc.exe` pipeline; actual blocking point unproven |
| Slow post-boot work | Prior capture took 82.188 seconds and a separate inspect took 106.219 seconds; exceeding the ceiling is possible, but not established as the cause |

The established harness limitation is missing intermediate comparison-stage
output and cooperative deadline checks between synchronous calls. Its external
watchdog bounds local waiting without proving remote cancellation. This
explains the diagnostic gap; it does not identify the operation that hung.

## Actual twelve-step recovery matrix

**`4/12` counts recovery receipts, not Agent 3.2.82 acceptance scenarios.** PASS
below means a complete historical recovery receipt only.

| Step | Operation | Status |
|---:|---|---|
| 0 | capture | PASS |
| 1 | stop-for-snapshot | PASS |
| 2 | snapshot | PASS |
| 3 | start-after-snapshot | PASS |
| 4 | compare-after-start | UNKNOWN |
| 5 | marker | NOT RUN |
| 6 | compare-before-restore | NOT RUN |
| 7 | stop-for-restore | NOT RUN |
| 8 | restore | NOT RUN |
| 9 | start-after-restore | NOT RUN |
| 10 | restored | NOT RUN |
| 11 | provider-after-restore | NOT RUN |

Totals: **4 PASS / 0 FAIL / 1 UNKNOWN / 7 NOT RUN**.

The canonical product acceptance requirements remain in
[Task 13 of the approved plan](../plans/2026-10-03-agent-3.2.82-pre-fleet-hardening.md).
No canonical twelve-scenario Agent82 result matrix or final Agent82 acceptance
report was found. Clean Setup, legacy upgrades, compatible newer-core handoff,
low-disk, WSS-only failure/OTA, bad-candidate rollback, updater network isolation
and three hard-reset phases have no demonstrated PASS in this investigation.
Historical release results and CI cannot replace those proofs.

## Controlled reproduction and resume gate

**Stage B has not been executed.** A reviewed, instrumented single-scenario
package with remote child lifetime control and fresh provider/hypervisor
reconciliation is still missing. Replaying the old silent whole-run harness is
not a tested workaround. This is outstanding work, not proof that reproduction
is impossible.

The proposed scenario is one instrumented read-only `compare-after-start` on
the isolated test VM, using a fresh diagnostic identity and explicit bindings
to the preserved baseline, source, input and snapshot. Before execution:

1. Refresh MSI/SCM/update/provider/control state and verify snapshot/configuration,
   volume identities and available capacity.
2. Create and verify the required pre-reproduction snapshot.
3. Independently review the scenario package.
4. Record sanitized ENTER/RETURN frames around exact-count reads, wire/hash/decode,
   helper entry, baseline operations, Facts groups and each native call.
5. Keep the 120-second scenario ceiling, an external hard watchdog and explicit
   owned remote child termination/exit confirmation. Local SSH retirement alone
   is insufficient.
6. On timeout preserve frames/logs/exact process evidence before cleanup, return
   UNKNOWN and dispatch no automatic retry, restore or full Task 13.

**Runtime change: NO at present; evidence does not justify one.** This does not
exclude a later Agent/Setup/MSI defect. No incident-fix commit, RED-to-GREEN hang
regression or harness-fix acceptance exists. A proven runtime defect must be
recorded as a release blocker and fixed under a new immutable release identity.
Published 3.2.82 bytes remain unchanged.

Resume requires verified preserved checkpoints and current state, an established
cause or tested safe workaround, proven diagnostic/watchdog control and
independent review of the actual single-scenario result. Cleanup/report review
PASS is not resume approval. **Mass rollout remains prohibited until complete
READY FOR FLEET.**

## Verification and review

Independent local review verified 234 original record anchors, 61 source entries,
305 prerequisites and 28 post-cleanup observation anchors. It also independently
verified command reconstruction, collector bindings and reported state/log facts.
No Critical or Important report defect remained in its reviewed scope.

The protected dossier's 28-file SHA-256/size manifest was created and read back
after the review. Python AST checks, retained JSONL parsing and exact command
reconstruction checks passed. No product tests were run because product code
was not changed. Reproduction, incident regression and resume acceptance remain
outstanding. See the [independent review summary](2026-10-09-task-13-hang-rca-review.md).
