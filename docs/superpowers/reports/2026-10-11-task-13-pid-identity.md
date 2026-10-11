# Task 13 PID Identity Guard Correction — execution evidence

Final operational status: **BLOCKED / UNKNOWN**, before seq04 comparator dispatch.
The implementation and both exact-source packages received independent PASS.
The read-only full gate passed; the separately authorized execution step then
failed its mandatory fresh canonical preflight. No receipt04 or resume gate exists.
The recovery launch claim is consumed and no retry was made.

## Proven reason for the two present processes

Read-only native observations identify `service_update.exe` and `sshd.exe`.
Their native creation times are respectively 2026-10-09T06:48:09.1198880Z and
2026-10-09T06:48:09.0903065Z. Both follow the pinned accepted absence witness
at 2026-10-09T06:45:30.5166660Z and fall inside the receipt03 boot bracket
06:47:46.566919–06:48:16.189832Z. Therefore both occupied numeric PIDs are
**PID_REUSED**, rather than surviving original instances.

Protected raw evidence retains PID, full native image, native creation FILETIME,
parent PID, SessionId, handle count and repeated retained-handle liveness checks.
Selected parent CIM metadata has SessionId and creation time; its image was
unavailable. No command-line arguments were collected. No service, process or
configuration intervention was performed on sshd.

Fourteen original slots have no saved creation time. One pair member has a saved
native/CIM creation time; the other has no own saved creation time. Missing values
were not reconstructed. The pinned absence witness supplies the alternative
instance-separation proof, with repeat native identity and race checks mandatory.

## Implementation and preserved invariants

- Four controller-computed states: ORIGINAL_PROCESS_ACTIVE, PID_REUSED,
  PROCESS_ABSENT and IDENTITY_UNKNOWN. Original-active and unknown block.
- Read-only native observer takes two samples while retaining the first handle.
  Native creation ticks must agree exactly. CIM's microsecond projection must
  agree with the native value; same-microsecond replacement cannot bypass native
  equality. Access errors, malformed data and exit/restart races remain unknown.
- Identity is a mandatory eighth raw constituent of every operational current
  gate. Exactly two original known/pair PID predicates are substituted; marker,
  leaf, observer, error and other original conditions remain mandatory.
- A guard-only package cannot launch seq04. The separate execution package binds
  the actual human request and eight pinned artifacts of the earlier full gate.
  That admission never substitutes for the new canonical preflight.
- Original plan/seal, receipts00–03, baseline, snapshot, source pins, the new
  1200-second validity window, native supervision, watchdog and publication
  prerequisites were preserved. No old expiry or seal was patched.

GitNexus endpoint_platform query was consulted before source exploration. The
additive local continuation changes were verified against source and tests;
there are no changes to external repository contracts.

## Verification and independent review

RED→GREEN covered PID reuse, denied identity reads, reuse with a live SSH service,
exit/restart races, unknown/original-active rejection, marker/leaf tampering,
changed gate pins and permission-scope refusal. The owned native observer test
exposed singleton CIM collection handling and timestamp precision before GREEN.

Final command (Python3.12, historical-root environment supplied):

```powershell
$task13Tests = @(Get-ChildItem tests/tools/test_task13_continuation*.py | ForEach-Object { $_.FullName })
& $task13Python -B -m pytest @task13Tests tests/tools/test_task13_process_identity.py tests/tools/test_task13_msi_profile.py tests/tools/test_task13_watchdog.py -q
```

Result: **227 passed in 165.44s**. Correction targeted verification: 71 passed.
Independent correction verification: 71 passed. Independent separate-admission
verification: 11 passed, with two app-thread tests replaced by direct inspection
of the actual human permission frame. Root verification ran all 227 tests.
Full implementation diffs were inspected and `git diff --check` passed.

| Source commit | Message | Included scope |
| --- | --- | --- |
| fa390bb6c990802dd031f4604e19ef1f39155ec9 | fix(canary): distinguish original process identity from PID reuse | Native observer; identity classifier; read-only entry; continuation integration; tests; design/plan/operator docs (16 files) |
| 3be6ea3f2b36f7c4bfa2827a707feb0c24f240f2 | feat(canary): admit separate seq04 after reviewed identity gate | Gate admission; bundle/loader/permission binding; tests; design/plan/operator docs (8 files) |

## Runtime outcomes

Read-only observation completed at 2026-10-11T13:40:51.628182+00:00:
READY_FOR_SEPARATE_SEQ04, 14 PROCESS_ABSENT and 2 PID_REUSED. All eight raw
constituents and immutable prefix were independently reconciled at the observation
time. Native controller exit0 and empty stderr were retained. No claim or seq04
execution authority was created by this observation.

After the second independent exact-source PASS, one separate execution step was
attempted. Its fresh canonical preflight produced 13 PROCESS_ABSENT,
2 PID_REUSED and **1 IDENTITY_UNKNOWN** (reference slot10, zero-based).
That row contains RuntimeException, first=null, second=null and no retained-handle
result. The concurrent current observer reported absent/error-free, which cannot
replace missing native identity evidence.

All eight transports completed with exit0 and empty stderr. The native identity
transport lasted 2.609 seconds; later rows and parent metadata completed normally.
The saved data does not establish which first-sample native/CIM operation threw.
A timeout, access denial or process race must not be claimed as proven RCA.
The observer intentionally retains only the exception type, so exact RCA remains
UNKNOWN. The classifier and original current gate correctly rejected the row.

Native root exit1 and supervisor UNKNOWN were retained. Failure occurred before
preflight aggregation, watchdog preparation, comparator intent/dispatch and
original seq04 dispatch claim. No receipt04, completion publication or resume
gate was created. The consumed shared recovery launch claim was preserved;
no new VM contact, claim removal or repeat execution followed the failure.

Final independent offline failure audit: **PASS for fail-closed integrity**.
It reproduced the guard refusal, matched root PID/birth to the capsule, verified
signaled native wait/exit1, complete streams and timed_out=false, checked all
eight result/intent pairs and the consumed recovery claim, and verified unchanged
historical bytes. A separate local protected-store audit confirmed the same claim,
identity classification and absence of an original seq04 dispatch claim.

## Evidence SHA256

Raw identities and topology remain in protected local evidence rather than this
tracked report. Hashes below identify the preserved bytes.

| Artifact | SHA256 |
| --- | --- |
| Original plan | bbddf13f084c6be9c7fed8fc2041df88953aabb33915ce12631eeab0f1c7fa5d |
| Original seal | 6f30d2b3698498f4daa55aa2a8f1fd6e4181e3a20498c8ce8a7de4da37d74590 |
| Receipt03 tip | cdd42d87efa105f78957240838b96e0232784869d36f5335396aa341168cf4fd |
| Baseline | cdbdf079698747b2af32e7749291388099f04275e10c13995616c8d1206e1534 |
| Snapshot | 923000023d7996498bd6ce51b822a171e626c04335c9403cd2e1f7d1e59074d5 |
| Original source closure | 6abe8fc674d09f2f0d1deabc07494d54c0b2d6d16ed2fa307c269900227226cb |
| Process reference registry | 0a2ef397cb48f8f04d9f4d993ce42eb8e1e1986b095a940b3e368b6bb633a7a5 |
| Correction closure | 97ea1d0e52b0d4540ef94590faa20236c1af7ab08899dfdd3f763d66952dddc1 |
| Correction independent review | 96cf890749bb8541bcb939278fb66fd3eef0f815f03e3cbb3f96eed91d37bf4d |
| Correction review trust | e6addf8c23592fe02f6b02432570ce719c5fe97b0ad91e67d3636b09fe48cfb8 |
| Read-only window | f6a4eb76317bf9ca62b40c9a4235a9fd24ce6f13670b831a964fe3c98a67eb20 |
| Read-only full preflight | 81a6e331525bf15ee79c7d1b8131429397f5a8db7b6799e9d0335ed39138268b |
| Read-only verdict | 5886392602065777fe3c9550e3b18a8f91a785d051062c80df68dd127089f30a |
| Read-only controller transport | 44d204bc3cbdd5cf7082a05790bd0d59665325d7db23fcd2ceea27450b2ac188 |
| Separate execution closure | ef34fc154470552e32221e882f587be2e330fe2243bb4e9b4e70023aff35b2db |
| Separate independent review | db71ba0f13549cace91abbd98dd374c3ccb6fc4c4826733ad1cabfe8c3bf2ce3 |
| Separate review trust | 77f05124bda72133f1100aad40a7ddbf20a88417abcdd416de0bc690ba88c0c1 |
| Separate capsule | 66acd1d517485199df593ab9e536fcbac26729041468d437ea202d0239c3f314 |
| Failed native identity envelope | 0f25479b4befc5b4e5b2791a01d8d7cdb836b2d3dc16ff943365016e6b018945 |
| Failed root transport | 4e6d1f233f5ca828040b6212fc4f8b475c90864e6ad28dd17b7fe24b9a9c5a82 |
| Supervisor UNKNOWN | b03700be53d69a59d1d24f713243dc729b3c106adbb1fa8165ee037a28e0db9a |
| Outer supervisor observation | 78690dee568c9a69a77f47ad9b34c837004c5780d7672c5bfacb3ff46010e45a |

This establishes the PID reuse correction and fail-closed behavior, not Task13
Windows acceptance or READY FOR FLEET. Seq04 acceptance and the resume gate remain
unverified. Any future recovery needs an additive independently reviewed protocol
that preserves this UNKNOWN and the consumed launch claim.

## Files included in source commits


Commit fa390bb6c990802dd031f4604e19ef1f39155ec9 :

- docs/architecture/task13-continuation-v1-operator.md
- docs/superpowers/plans/2026-10-11-task-13-pid-identity.md
- docs/superpowers/specs/2026-10-11-task-13-pid-identity-design.md
- tests/tools/test_task13_continuation_loader.py
- tests/tools/test_task13_continuation_readonly.py
- tests/tools/test_task13_continuation_reconciliation.py
- tests/tools/test_task13_continuation_recovery.py
- tests/tools/test_task13_process_identity.py
- tools/canary/Observe-Task13ProcessIdentity.ps1
- tools/canary/task13_continuation/loader.py
- tools/canary/task13_continuation/operations.py
- tools/canary/task13_continuation/permission.py
- tools/canary/task13_continuation/process_identity.py
- tools/canary/task13_continuation/readonly_gate.py
- tools/canary/task13_continuation/reconciliation.py
- tools/canary/task13_continuation/supervisor.py

Commit 3be6ea3f2b36f7c4bfa2827a707feb0c24f240f2 :

- docs/architecture/task13-continuation-v1-operator.md
- docs/superpowers/plans/2026-10-11-task-13-pid-identity.md
- docs/superpowers/specs/2026-10-11-task-13-pid-identity-design.md
- tests/tools/test_task13_continuation_gate_admission.py
- tools/canary/task13_continuation/bundle.py
- tools/canary/task13_continuation/gate_admission.py
- tools/canary/task13_continuation/loader.py
- tools/canary/task13_continuation/permission.py
