# Recovery F: one actual seq 04 dispatch, acceptance refused

Implementation: `2fa9b36f4ec2abd7497193cb3fdbbb138ba68477`.
Protocol source SHA256:
`bca862501838877297c7b0f35e658ee45ed9fbecaaaa91ca4eb1d0b4fab4a18e`.

The existing actual human request and explicit continuation clarification were
bound into recovery v2 without copying an authorization JSON. No authorization
clock was renewed. Earlier consumed claims and failed attempts were preserved.

## Reviewed admission and sole invocation

Fresh P observation and its independent admission reviewer both settled with
native exit zero. Seven actual transports represented eight logical captures.
The gate checked UTC was 2026-10-12T17:20:16.467985+00:00; its unchanged finite
expiry was 17:50:16.467985 UTC. The final gate SHA256 was
`cb5e72540425caf9c1c3718c3cbdd47f5708ea784899a7805504d7d94181e1c3`.
Its maximum command length was 7,796 UTF-16 units including NUL.

The independent F execution review verified 104 source entries, 2,879 runtime
files, nine exact sealed outer packets and the original inner wire. Execution
closure SHA256:
`44cf8d5beda07df51073b9822dcd01e16060ed8c874f2d22d38cb778c5845ed8`.
Review SHA256:
`faae8953883bc054ff9ccb9f418f2e4106577bb3632c4251ad57160f1e76829f`.
Recovery-review SHA256:
`67f29f671cd0259fc114da24c06ac6524a64ae489c0d3a2489477be7449bf1af`.
Trust SHA256:
`ac987831876828828ac63c6063d60b2f2d0496cf49b2049b51443c91c7abf18f`.

The fixed read-only final prelaunch check passed with 1,204.83573 seconds
remaining, exceeding the unchanged 1,020-second caller reserve. The exact
creator command measured 325 UTF-16 units including NUL, SHA256
`ba8d73e58a15740688aecfefb3a06d8cd6f25bf8ded68f42b3e076b085ba0603`.
The operator invoked the protected creator exactly once. There was no retry.

## Actual outcome and limits of the cause finding

The actual compare-after-start transport dispatched at
2026-10-12T17:35:51.205640+00:00 and finished at
2026-10-12T17:37:43.686421+00:00. It confirmed stdin delivery, returned exit
one and a structured `RECOVERY_GUEST_FAILED` result with
`safeErrorType=RuntimeException`. Stderr was empty. Its stdout SHA256 was
`14a85f66c05d9adbaef6a06dbbaeef64493a869a7e51841fbce2cb34dd801049`.

The failure evidence collector settled normally and retained all five expected
guest evidence files. The watchdog retained the actual diagnostic process:
wait zero, exit two, confirmed exit, `terminated=false`, elapsed 107,633 ms,
`capture_complete_before_exit=false`, and no capture error. The watchdog did
not terminate the process. Neither timeout nor sealed-reader failure is proven.

The last journal entry was `ENTER FACTS.CACHE_FINAL` at
2026-10-12T17:37:42.5314368Z. The unchanged helper then constructs its final
MSI facts, returns Facts, serializes the result, checks exact baseline equality,
and constructs public proof. These boundaries have no distinct terminal journal
entries in the captured failure. The catch deliberately emits exception type
only. The exact exception message and failed predicate were not retained.
The underlying cause is therefore **UNKNOWN**; cache inspection, serialization,
baseline mismatch and public-proof failure cannot be distinguished from this
record. Original RunId parameters were preserved; journal continuation identity
is separate and is not evidence of a Facts RunId mismatch.

The child exited abnormally. The supervisor refused canonical acceptance with
`actual recovery root complete normal exit required`. There is no accepted
receipt 04, resume publication, or RootCompletion. Source/test/admission PASS
does not establish seq 04 acceptance.

## Durable boundary

Both new recovery launch and dispatch slots are occupied. Their irreversible
burn semantics remain binding, including after a failed guest workload. They
must not be deleted, restored, replaced, reissued under another continuation,
or bypassed with a diagnostic route that repeats the comparator.

The historical three consumed claims, original plan/seal/deadlines/receipts
00–03, sealed Facts, baseline and snapshot are preserved. The complete claim
directory now includes the two intentionally new permanent records; its old
whole-tree hash must not be represented as unchanged after this dispatch.

Steps 05–11 require an accepted, native-settled receipt 04 and remain blocked.
No marker, restore, MSI/Setup invocation, runtime modification or mass rollout
was performed by this attempt. A fresh gate cannot authorize a retry through
the occupied one-slot protocol. Read-only investigation must preserve this
outcome and must not confer execution authority.

The independent historical outcome audit settled with exit zero. Its durable
SHA256 is `4186b577b934c213e0106d6f5dc7e3f4ab8c224e0e6824c90179c385594e4946`.
It verified all 104 sources/2,879 dependencies, eight readiness records, four
full joint states, and 31 actual transports: 30 completed normally and the one
actual comparator dispatch returned UNKNOWN. The child retained handle showed
wait zero/exit one, complete bounded streams and no timeout. Independent native
observations found creator and child absent; no retained creator wait result
was invented. The original/old-three-claims/prior-evidence projection retained
its exact preclaim SHA256
`49b3707bd72a001c730c77c39a0608d204a13a80c83bb58c812120cabb3a3ac1`.

The physical launch slot is 2,511 bytes, SHA256
`3b0ebca8f4b3d3ffeb396803dadfbf3bc2bc47edb2f7a22f24f518c7e014be77`;
the physical dispatch slot is 1,891 bytes, SHA256
`2bbdf3b2e26c0542ce17d860f6ed2e5bbedf2c34f1868796d6268d1b277fc860`.
Both match their exact owner records. The actual pure read-only unused-slot
check measured `DISPATCH_COMMITTED`; `require_unused_slot` refused with
`recovery slot already occupied; observation only, no retry`.
Actual execution acceptance and forward admission are **NO-GO**; missing
receipt 04/RootCompletion additionally deny forward admission. No replacement
NO-GO gate was created, and P's historical gate remains unchanged.
This audit used recorded historical timestamps and did not renew permission,
call a live admission gate or dispatch another target workload.

The implementation's six affected suites had passed 238 tests in 89.86 seconds,
including native Windows PowerShell 5.1 behavior. Independent source/security
review passed 44 tests in 53.10 seconds with no Critical/Important finding.
Those results precede this real guest failure and remain implementation
verification only.
