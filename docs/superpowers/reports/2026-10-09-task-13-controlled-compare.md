# Task 13: controlled single comparison and watchdog correction

Date: 2026-10-09. Product baseline:
5d36fd383328cba10d2d3f6b55fe2e8489b8fb31.
Decision: **BLOCKED**. Diagnostic evidence/control review: **PASS**.
Comparator acceptance: **UNKNOWN**. Runtime change needed: **NO on current evidence**.

This supplements the [initial forensic report](2026-10-09-task-13-hang-rca.md).
Private VM identities, commands, journals and source/input bindings remain in
protected external artifacts. No production device or server operation was changed.

## Scope and preparation

Exactly one controlled compare-after-start scenario was attempted. Before it,
an initial diagnostic bootstrap failed because PowerShell execution policy
blocked dot-sourcing the journal file. It exited before stdin reading, payload
decoding or comparator invocation. Both wrapper processes had shutdown events
and were absent; the waiting watchdog exited with no registered target.
That refusal and its consumed dispatch guard were preserved separately.

The correction embeds the sealed journal function in the encoded wrapper.
A local full-packet test under process policy Restricted passed stdin,
decode and ScriptBlock creation, then correctly refused the wrong machine.
The VM execution policy was not changed. The corrected package received a
separate independent source/control review before its sole dispatch.

Fresh preflight verified the dedicated VM, unchanged boot, at least 10 GB free,
and the retained baseline hash:
cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534.
The existing pre-scenario snapshot was reused; no new snapshot or restore was
performed. Saved VM configuration, snapshot metadata and intrinsic volume
identities matched the sealed checkpoint; active hypervisor tasks were empty.

| Boundary | Before and after the scenario |
|---|---|
| Agent / SCM | Agent Running/Automatic; Updater Stopped/Manual |
| Windows Installer | msiserver Stopped/Manual; no msiexec processes |
| Transactions | Checked Installer InProgress, Rollback/Scripts and reboot-pending keys absent; fixed installer fence absent |
| Update state | Pending update, startup attempt and terminal outcome absent; retained history, reports and startup-confirmation hashes unchanged |
| Checkpoint | Baseline bytes/hash unchanged; marker absent; boot unchanged |
| Hypervisor | Configuration, keyed snapshot records and volume identities unchanged; no active tasks |

The journal is separate from stdout, under a protected root with only
SYSTEM/Administrators access. Every frame includes diagnostic run, PID, native
birth, sequence, UTC and elapsed time. ENTER/RETURN bracket stdin reads with
counts, payload decoding, ScriptBlock creation/invocation, baseline operations,
Facts stages and 58 statically selected native/COM/SCM/CIM call sites.
Frames are flushed through FileStream.Flush(true) and WriteThrough.
See [Microsoft's file-buffer documentation](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream.flush?view=netframework-4.8.1).

## Actual result and evidence limits

The independent SYSTEM scheduled watchdog survived the SSH transport and
retained a native handle bound to the registered child PID, creation time and
PowerShell executable. It collected a journal prefix and live process state
before termination, then verified signaled process state and exit code on the
same handle. This follows the
[Windows process termination/handle semantics](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process).

| Observation | Result |
|---|---|
| Scenario result | Controlled timeout; stdout 0 bytes, stderr 0 bytes, SSH exit 1 |
| Stdin | 73 completed reads, all 295,416 wire bytes received |
| Decode / helper | Payload validated/decoded; ScriptBlock created; comparator entered |
| Journal | 33,343 valid contiguous frames; 6,776,214 bytes |
| Completed native calls | 16,433 ENTER/RETURN pairs; longest observed duration 161 ms |
| Reached group | MSI_TABLES entered at 45,458 ms |
| Pre-kill capture | 32,725-frame exact prefix; last frame ENTER FieldCount at 117,794 ms |
| Final retained frame | ENTER StringData at 119,293 ms; only 3.7622 ms before kill |
| Native termination | Exit 124, wait result 0, confirmed on retained handle |
| Capture timing | Durable capture completed 1.3609601 s before termination |
| Birth-to-termination-request interval | 120.0251971 s, including 25.1971 ms scheduling overshoot; exit confirmed separately |
| Settlement | Child, forwarding parent and watchdog absent; no exact wrapper matches; one-shot watchdog task finished successfully |

The pre-kill FieldCount call subsequently returned in the final journal.
Fetch, FieldCount and StringData calls continued to return through the final
milliseconds. Thus the run exceeded its budget while making progress.
An unmatched ENTER at forced termination does **not** establish a native hang.
The instrumented table scan, including per-call durable logging, consumed the
remaining budget; the contribution of instrumentation overhead was not measured.

The exact historical cause of PID 5228's hang remains **unestablished**.
This run does not prove an MSI transaction/mutex/RPC deadlock, nor exclude a
different failure in the historical silent wrapper. It shows that this packet
passed stdin/decode and that current MSI table calls were returning. No whole
Task 13 retry, marker, restore, second comparator or Agent82 scenario followed.

## Watchdog fix and RED-to-GREEN

The executed private package is frozen and retains its actual 25.1971 ms
overshoot. It is not retrospectively described as satisfying an exact 120-second
ceiling. A separate diagnostic harness correction is included as
[Watch-Task13DiagnosticProcess.ps1](../../../tools/canary/Watch-Task13DiagnosticProcess.ps1):

- initiate native termination 500 ms inside the requested ceiling;
- keep capture on a background thread, independent of native wait/kill;
- freeze capture-completed truth before termination, with timestamps;
- refuse unprotected/reparse roots and mismatched run/native birth/image;
- retain explicit incomplete capture on missing/empty/oversized journal or write failure;
- confirm exit through the retained handle, never by PID disappearance alone.

The tool does not launch a workload. Its caller must verify the dedicated VM,
create a fresh protected root, start an independent watchdog, wait for readiness,
and atomically publish the owned child's identity.json with exact root, run,
PID and native FILETIME birth. The child must wait for armed proof before work.
Capture failure remains UNKNOWN and must not authorize retry or resume.
SyntheticCaptureStall is reserved for local regression tests.

RED: the local ceiling regression failed against the pre-margin implementation:
observed synthetic process lifetime **3.0096276 s > 3 s**.
GREEN command: python -m pytest tests/tools/test_task13_watchdog.py
tests/canary/test_verify_installed_windows_agent.py -q.
Result: **70 passed**, including ten new Windows watchdog cases for hard ceiling,
capture stall/write failure, missing/empty/oversized journal, stdin wait,
normal exit and wrong run/native birth.
PowerShell parser and diff checks passed. Local helper instrumentation tests
also preserved typed native returns, false values and ref mutation.
Checks ran on the available Windows host with Python 3.14 and pytest 8.3.4;
the repository's pinned Python 3.12 environment was unavailable. These are
targeted harness/canary checks, not a full product suite or exact-release CI proof.

The corrected 500 ms-margin watchdog was tested on owned local synthetic
processes only. It was **not** used for a second VM comparison. Ordinary
scheduling margin is not evidence of control over a frozen OS or host.
No Agent/Setup/MSI code or published 3.2.82 bytes were changed.

## Checkpoints and resume decision

The [historical twelve-step matrix](2026-10-09-task-13-hang-rca.md#actual-twelve-step-recovery-matrix)
remains unchanged: four confirmed recovery receipts, comparison UNKNOWN,
seven steps NOT RUN. These are recovery steps, not twelve Agent82 acceptance
scenario PASSes. The diagnostic attempt did not issue a new canonical receipt.
No canonical twelve-scenario Agent82 acceptance matrix was discovered.

Independent review verified frame identities/sequences, capture prefix,
read counts, native pairs, capture-before-kill timing, native exit and current
checkpoint/MSI/SCM/update/hypervisor settlement. Control/evidence PASS does not
promote comparator UNKNOWN or approve resume.

**BLOCKED**: historical root cause or a proven safe workaround is still missing;
the corrected watchdog lacks live VM validation; complete provider/server
reconciliation and canonical acceptance remain outstanding. Mass rollout remains
prohibited until full **READY FOR FLEET**.
