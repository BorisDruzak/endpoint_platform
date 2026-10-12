# Task 13 command transport hardening

Scope: additive canary transport only, based on `0f747edee76bd29fb38d0462a790a4b5fcfcdbcc`.
No seq04, runtime 3.2.82 change, deployment, marker, restore or mass rollout.
Existing consumed claims remain consumed. Historical RCA remains UNKNOWN.

## Implementation

The actual retained prepare builder generated **34,172 UTF-16 units including
the terminating NUL**. The original preparation attempt failed after claims had
already been consumed. Those claims and the failed bundle were preserved.

Delivery now reuses the pinned historical controller's exact-count gzip/base64
JSON packet factory. Only a short verifier is carried through EncodedCommand;
the complete sealed payload is sent through stdin. The verifier requires exact
wire length, EOF, wire/body/source SHA-256, bounded decompression, strict UTF-8
and the original string parameter pins before invoking a ScriptBlock. Input
has a fixed ten-second total deadline, including the EOF probe. Pending native
reads cannot indefinitely delay the original workload watchdog.

For the workload, the original inner wire becomes a StringReader only after
the outer packet has been fully verified. Wrapper, comparator, capsule,
identity, journal, receipt and watchdog predicates are unchanged. New bootstrap,
packet, verifier and bindings belong to the additive source closure.

`validate_command` measures subprocess.list2cmdline serialization in UTF-16
with NUL, checks the remote shell command separately, and refuses at 8,192 units
with `COMMAND_LINE_TOO_LONG`. Every bound operation is checked before the launch
and global dispatch claims; the exact command length and digest are checked
again immediately before transport Popen. The root supervisor also repeats its
bound plan and root command check immediately before launch. No cmd.exe or
ExecutionPolicy changes were introduced.

## RED to GREEN

The first transport test run was RED (14 failures): missing stdin delivery,
missing pre-claim admission and attempts to reach the mocked process launcher.
Two independent-review reproductions were also RED: an open stdin could block
before watchdog startup, and a short argv substitution could reach Popen. Both
received regression tests and fixes.

The final focused transport/capsule run passed **43 tests** on Python 3.12.14
and native Windows PowerShell 5.1. It includes the exact historical builder,
UTF-16/non-BMP/quoting/NUL boundaries, large payload and unchanged inner stdin,
bad wire/body length or SHA, wrong source/parameter pins, truncated/appended
stdin, open stdin with/without the complete frame, final command substitution,
and refusal before either claim. Existing capsule/attestation/identity/clock
negative tests remain fail closed.

Commands use the verified Python 3.12 operator interpreter and a local retained
historical input supplied through TASK13_HISTORICAL_ROOT:

```text
python -B -m pytest tests/tools/test_task13_command_transport.py tests/tools/test_task13_continuation_authority.py -q --tb=short
git diff --check
```

The complete applicable Task13 regression selection passed **269 tests** in
221.91 seconds (11 deselected: nine historical scope/state-dependent cases and
two tests outside Task13). The selection was:

```text
python -B -m pytest tests/tools -q --tb=short -k 'task13 and not test_actual_execution_request_has_distinct_scope and not test_actual_execution_permission_binds_independent_admission and not test_caller_quote_cannot_turn_guard_scope_into_execution and not test_separate_permission_binds_actual_message_and_prior_gate and not test_capture_readonly_recovery_preserves_consumed_claim and not test_changed_consumed_claim_blocks_readonly_recovery and not test_changed_readonly_record_refuses_under_retained_handles and not test_actual_new_request_scope_denies_execution'
```

The first full relevant legacy run had 243 passes and 11 failures. Two synthetic
fixtures were updated to provide the newly mandatory bound command plan. The
remaining nine failures were separately reproduced on the clean immutable
baseline: they expect prior app-session seq04 authority and pre-consumption
claim state. The present request does not grant that authority, and existing
claims are consumed. Permission/recovery/replay guards were not relaxed. This
is not a claim that the unrestricted, state-dependent legacy suite is green.

## Independent review and closure

Two material findings were fixed before acceptance: bounded raw asynchronous
stdin reads now require EOF, and final command validation compares the exact
digest as well as UTF-16 length. The reviewer independently reran all **24
transport tests** and all **11 native synthetic cases** locally, including both
open-stdin cases at the unmodified production ten-second deadline.

Final independent source review: **PASS**, no Critical/Important findings.
The reviewer held and verified 89 execution entries and 2,879 runtime files,
matched the implementation worktree, regenerated all nine packet/bootstrap
derivations, and checked the unchanged inner wire and historical preservation
snapshot. New protected review/trust records authorize only synthetic and
read-only observation; neither is a seq04 execution review/capsule.

| Artifact | SHA-256 |
| --- | --- |
| Final observation source closure | `f219ff086d1cf1623107bb66a0638ed2ae8d3d45eaf7a57dce1c68e0ba8c5cac` |
| Independent review | `01119586d1997c0da8666d1ae23a36cabdaf0e833e729470b70af380f3ccd137` |
| Review trust | `ac692cc8aefee49b1612c6f47dd19b2574e831e897761c9fe13b46df5aa63a64` |

The read-only/synthetic acceptance entry retains the reviewed source/runtime
and historical manifest handles, checks the original four checkpoints, and
compares all old claims and failed/prior read-only evidence before and after.
The final source review also explicitly permits the separate inventory
diagnostic observer and excludes execution authority.

The first synthetic VM observation remained UNKNOWN: a 3,226,996-byte outer
test packet ended after 11.375 seconds without confirmed stdin or exit. Its
cause was not proven. No runtime or claim changes were made. An initial
read-only observation passed management, provider, guest, current and process
identity constituents, but inventory exited with UNKNOWN; it is not a full
preflight PASS. Both observation records were preserved.

The test-data compaction initially regenerated a gzip packet timestamp. Review
detected changed wire hashes and refused that candidate before target contact.
The replacement copies the exact first reviewed eleven case dictionaries and
uses lossless common-wire/bootstrap references, expanded before the unchanged
stdlib fixture. Production code and input deadlines did not change for this
acceptance adjustment. Inventory diagnostics are a separate read-only observer
copy with stage annotations and an explicit Console catch output; original
inventory guards and its exit-on-failure remain unchanged and alone govern
canonical preflight admission.

## Final native acceptance

**SYNTHETIC_TRANSPORT_PASS** at 2026-10-11T17:25:40.679799Z. The dedicated
Windows VM received and verified the entire **486,664-byte** outer packet,
larger than the real sealed workload packet (452,108 bytes). SSH stdin was
confirmed complete, exit 0, no stderr, total 28.609 seconds. The fixture used
Python **3.12.10** and Windows PowerShell **5.1.26100.9444**. All eleven cases
have retained native WaitForSingleObject=0, GetExitCodeProcess, and stable
PID/birth evidence from the same process handle.

- Long sealed payload: exit 0; exact original synthetic inner stdin preserved.
- Truncated/appended input, wrong wire/body length or SHA, wrong source or
  parameter pins: exit 2, no invocation output.
- Partial-open and complete-open without EOF: exit 2 after 10.328 seconds each.

Final full commands, including SSH arguments, quotes and NUL:

| Operation | UTF-16 units |
| --- | ---: |
| Prepare | 7788 |
| Workload | 7788 |
| Inventory / collection (maximum) | 7808 |
| Guest / current / process identity / guest clock | 7788 |
| Synthetic parent | 7796 |
| Nested synthetic Python command | 5340 |
| Management | 549 |
| Provider | 227 |

The maximum is below the conservative 8,192-unit transport ceiling and leaves
24,959 units below the Windows 32,767-unit system ceiling. Remote command
serialization is also checked before claims and dispatch.

**READ_ONLY_CANONICAL_PREFLIGHT_PASS** at 2026-10-11T17:26:55.453853Z. The original
inventory observer, without diagnostic substitutions, passed with all eight
native transport constituents: management, provider, guest, inventory,
current, process identity, guest clock and management clock. Canonical state
validation checked ownership/runtime/identity/clocks, baseline, snapshot
metadata/volumes/config and marker absence. The four-checkpoint prefix,
including sealed guest Facts, original plan/seal and historical receipts,
was reverified against its pinned source closure.

| Retained artifact | SHA-256 |
| --- | --- |
| Synthetic result | `5d49e6a49b1c052e6769a5ac8317d253abce06c1877070534f8c98a924211afd` |
| Synthetic verdict | `f5ad70841c2fc891b2f5bf5ee8bb5ec1f1557ee1f2c84b9b3195f7dc26e179d7` |
| Canonical preflight | `8fd94cb831c637f3dca5a84a5b68ac189e8391b86165a4b09b5f6aecd88234c7` |
| Canonical preflight verdict | `e8a2bafb62e76aa3ad02442c26153bf9e4c663ef65ef52ef49ca437d79e9e149` |
| Before / after preservation | `49b3707bd72a001c730c77c39a0608d204a13a80c83bb58c812120cabb3a3ac1` |
| Original plan | `bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d` |
| Original run seal | `6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590` |
| Original receipt03 tip | `cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd` |
| Baseline | `cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534` |
| Snapshot identity | `923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5` |

Every completed observer reported seq04_authorized=false, seq04_dispatched=false,
claims_consumed=false, old_claims_unchanged=true and runtime_changed=false.
No old claim was restored; the earlier failed evidence remains unchanged.
The first observation failures' causes remain UNKNOWN despite the later PASS.

Independent retained-result audit: **PASS**. The reviewer reran canonical
`validate_state` on the retained window/state at the recorded completion time,
checked all eight native exit/stdin/stderr results, exact argv and stdin
bindings, original checkpoint/Facts/plan/baseline/snapshot predicates and
before/after/current preservation hashes. The reviewer did not contact the
targets or modify the evidence.

## Change manifest

- `tools/canary/Read-Task13SealedPacket.ps1`
- `tools/canary/task13_continuation/{bundle,loader,operations,sources,supervisor,transport}.py`
- `tests/tools/test_task13_command_transport.py`
- `tests/tools/task13_transport_vm_fixture.py`
- `tests/tools/test_task13_continuation_authorized_execution.py`
- `tests/tools/test_task13_continuation_loader.py`
- `docs/superpowers/plans/2026-10-11-task-13-command-transport.md`
- `docs/superpowers/reports/2026-10-11-task-13-command-transport.md`

## Architecture

GitNexus was consulted before broad source exploration. Its indexed committed
baseline was `9144a26472239e5a4c61a79aacdabbda4ec961bc`; the branch-only additive
continuation transport was absent from that index. Important dynamic Python
factory and loader relationships were therefore verified against the retained
source and tests. No cross-repository API contract changed; no manual group
sync, reindex or managed-link changes were performed. Context7 documentation
was checked for Python 3.12 subprocess serialization and .NET asynchronous
stream read completion/wait semantics used by PowerShell 5.1.

## STOP

Transport acceptance does not authorize execution. A future attempt requires
separate authorization, exact independent source review and the existing
admission/replay/recovery gates. This work does not restore or bypass a consumed
launch/global claim, extend the expired original plan, synthesize receipt04,
or establish fleet readiness.
