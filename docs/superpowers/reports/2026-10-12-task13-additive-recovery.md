# Task 13: additive recovery admission v1 вЂ” readiness review

Baseline: `47b688c8cc926a9ac43e36426d69b07234f34cad`.
Implementation: `ed29d24d7b43bae7e96eb5186227f4f3809e66dc`, branch `codex/task13-recovery-admission`.
Initial protocol commit: `998ce160affd52d0c33b10bba61234c0312f88ba`.

Scope: separate versioned recovery modules. Ordinary admission/authority/transport,
source, receipt, continuation/identity/watchdog guards remain byte-identical to
baseline. Original plan, seal, deadlines, receipts00вЂ“03, baseline, snapshot, guest
Facts and all three consumed claims remain immutable. No Agent3.2.82, MSI, Setup,
marker, restore or rollout change. Historical identity RCA remains UNKNOWN.

## Admission semantics

The accepted historical control and source closure pin the physical original
root. A copied prefix cannot select another physical slot. Old claim presence and
exact byte identities are mandatory. One logical durable slot has exclusive
launch and dispatch transition records, keyed to original seal/tip/seq4 plus old
global claim hash; changing CID, deadline, request or protocol version cannot
create a second slot. CREATE_NEW occupancy is flushed before content. Empty,
partial, malformed, occupied or uncertain records permanently prohibit another
attempt. Crash/restart permits read-only observation and evidence settlement;
there is no repair, deletion, reissue or automatic retry.

Every command, shell limit, sealed stdin packet, source pin and runtime dependency
is verified before the first new claim, with exact command verification again
immediately before Popen. Authorization and fresh VM/provider/SCM/MSI/update,
identity, ownership and clock predicates are repeated before workload dispatch.
The parent records retained native child PID/birth; child checks registration and
parent liveness. Failed spawning/registration/communication permanently blocks
retry; any spawned child is killed, drained and checked through its retained
native handle before reviewed holds are released. Settlement uncertainty remains
UNKNOWN and never permits another attempt.

Recovery evidence and receipt schemas contain genuine historical consumed claims
and new recovery records; they reject fabricated legacy dispatch authority. Real
receipt04 additionally requires comparator, full collection/journal, native
watchdog normal exit, pre/postflight and independently observed normal root exit.
Synthetic receipt tests do not publish receipt04 or prove a real attempt.

## RED-to-GREEN matrix

| Check | RED / refusal | Verified result |
|---|---|---|
| Historical 34,172-unit command | Original prepare builder refuses before transport | Preserved historical failure; ordinary recovery remains NO-GO |
| New recovery with consumed prefix | Missing path / old global-claim refusal | Separate versioned historical admission accepts exact consumed state |
| Native concurrent consumers | Eight threads / four independent processes | Exactly one owned synthetic winner |
| Crash/restart | Native os._exit after empty/partial durable occupancy | Permanent fail-closed; no reissue |
| Replay / alternate slot | Changed CID/revision/request/deadline/global hash; copied root | All refused |
| Human authority | Implementation request, quote, changed latest message, wrong gate/CID/revision/pins/seq, expiry | All refused; no real execution authority |
| Packet integrity | Wrong size/SHA/helper/parameter pin, truncated/trailing packet | Fail-closed before any claim |
| Source / dependencies / command | Changed source or operation, missing dependency, oversized command | Fail-closed; no launch and unused owned slot |
| Capsule / receipt / watchdog | Wrong old claim, launch/dispatch/capsule/grant pin, deadline, incomplete stdin, journal, marker, native exit | Fail-closed |
| Post-spawn errors | Visible registration then flush failure; communicate failure | Kill/drain/native settlement before hold release; no retry |
| Historical Windows path spelling | Slash spelling absent as literal runtime key | Exactly one existing pinned file selected; all other arguments retained |

New recovery suite: **74 passed in 38.20s** on Windows / Python3.12.14:

```powershell
# TASK13_HISTORICAL_ROOT is read from the retained private control, never changed.
python -B -m pytest tests/tools/test_task13_additive_recovery.py tests/tools/test_task13_recovery_receipt.py -q --tb=short
```

The tests require Windows native storage and the retained private historical
prefix; private paths, identities and credentials are not committed. Process
crash/volume flush was exercised; no VM hard reset or power-loss certification
is claimed. The production recovery entry has no synthetic/alternate-root switch.

Full Task13 invocation before the final path-spelling regression addition:
**338 passed, 9 failed, 2 deselected**. Nine historical state/permission cases stay
unchanged and fail because their old expected human message or absence of the
now-consumed global claim does not match retained state. They are explicitly
excluded from the applicable regression selection, not weakened:

- `test_actual_execution_request_has_distinct_scope`
- `test_actual_execution_permission_binds_independent_admission`
- `test_caller_quote_cannot_turn_guard_scope_into_execution`
- `test_separate_permission_binds_actual_message_and_prior_gate`
- `test_capture_readonly_recovery_preserves_consumed_claim`
- `test_changed_consumed_claim_blocks_readonly_recovery`
- `test_changed_readonly_record_refuses_under_retained_handles`
- `test_actual_new_request_scope_denies_execution` (two parametrized cases)

The applicable regression excludes these names and two tests outside Task13.
The whole repository suite was not run; no service/API/agent runtime code changes.

## Exact implementation and test hashes

Protocol source digest: `c3c1f0823e22529b6fc67924af546ad716c640ad826ae7cbc6edac38a69ed5ba`.

| File | SHA-256 |
|---|---|
| recovery_admission.py | 9a44b389201d86c5bfdb3b4da519df78a7ef01d549744cde93a45d8c97892383 |
| recovery_bundle.py | 551a9e7dca036c340cae52e92ab2ac436c2c1a5288f7a90450d9203c47e95304 |
| recovery_gate.py | bb35918a16325981f52ae6ff99c6c601364776ab5145c2517dae1a733d722e90 |
| recovery_loader.py | 23ef4505de0c95dc1dd7d855d24f2daaa195b856d08d99f265451cd81f129d72 |
| recovery_permission.py | 38db66d1ffe710c70fd80d74de493ec677f3053ee98cd8ffce86d9f67d6ab85f |
| recovery_receipt.py | 154c87693fa1fb29f44b3c8108da0af76a14dee4affdf11d7a6cb7d45a395887 |
| recovery_supervisor.py | 3833a9858a8626d72ef3e028405201b19f3fdae61f711a903bea98e04e0db911 |
| test_task13_additive_recovery.py | 0e2fb1251e242e29beaf52d98253f21bcb60c3139b28a2ae90b8a3cb6178e9e6 |
| test_task13_recovery_receipt.py | 1f27a226ee118373522ea73c5a1e98d1c383ed75f2b268a08729d86f35db7eb3 |

## Source/security review and architectural impact

Fresh independent whole-source review closed two P1 findings with genuine
RED-to-GREEN tests: copied evidence selecting a second physical slot, and orphan
child after post-spawn error. Final path-spelling fix also reviewed. No remaining
Critical/Important source finding established. Exact committed bundle review and
native read-only admission review are separate evidence gates.

GitNexus was consulted before broad source investigation. Its committed main
index was `9144a26472239e5a4c61a79aacdabbda4ec961bc`; local recovery flow was verified
against source/tests because it is not in that remote index. No cross-repository
HTTP, Helpdesk or web contract change, synchronization or reindex operation.

## Retained source bundle A: read-only failure

Exact protected observation bundle: `task13-additive-recovery-observe-20261012-a`.
Source closure: `3df54a57198fa89673354e8504da9373f047ee7878d6c67ae91f6d97377471f1`;
85 execution source entries and 2,879 files of the previously accepted runtime.
Continuation ID: `bf4dbdd5-4eab-4ee3-91a1-509100b62684`.
Full maximum command: **7,796 UTF-16 units including NUL**; root command **325**;
maximum remote shell command **7,659**. Conservative layer limit is less than
8,192; Windows limit32767 leaves24,971 units. Full seq04 wire payload452,104 bytes
is sealed stdin and was verified offline; it was not dispatched.

Historical preservation digest before bundle creation:
`49b3707bd72a001c730c77c39a0608d204a13a80c83bb58c812120cabb3a3ac1`.
Old claims remain3, recovery slotABSENT. Original four checkpoints remain verified.

A failed its native read-only observation and cannot authorize execution.
The separately verified B gate appears below. This document grants no authority.

Applicable Task13 regression on exact implementation `ed29d24d7b43bae7e96eb5186227f4f3809e66dc`:
**343 passed, 11 deselected in 216.69s**. Selection:

```powershell
python -B -m pytest tests/tools -q --tb=short -k 'task13 and not test_actual_execution_request_has_distinct_scope and not test_actual_execution_permission_binds_independent_admission and not test_caller_quote_cannot_turn_guard_scope_into_execution and not test_separate_permission_binds_actual_message_and_prior_gate and not test_capture_readonly_recovery_preserves_consumed_claim and not test_changed_consumed_claim_blocks_readonly_recovery and not test_changed_readonly_record_refuses_under_retained_handles and not test_actual_new_request_scope_denies_execution'
```

Read-only observation A failed closed: native root exit1/wait0, full streams,
no timeout. The guest envelope returned certain exit1 with confirmed stdin and
empty stdout/stderr after11.453s; management/provider, inventory/current and
process-identity envelopes completed. No full preflight/gate was published.
Its complete failed evidence is retained; remote-stage RCA remains UNKNOWN.
A cannot be promoted to READY or authorize execution. A second fresh read-only
bundle B used identical protocol/guards and no claims; its PASS does not
establish the cause of A's failure or receipt04.

## Native read-only verification B

Bundle B: `task13-additive-recovery-observe-20261012-b`.
Implementation and protocol remain `ed29d24d7b43bae7e96eb5186227f4f3809e66dc` /
`c3c1f0823e22529b6fc67924af546ad716c640ad826ae7cbc6edac38a69ed5ba`.
Exact source closure:
`7d91791d57206e6d16f6fec9861d13b5c25177c3b9426c33b57437c8f5195adf`.
Continuation ID: `1795f237-94e0-42ca-a4e2-72696bc7f585`.
Independent source/security review:
`6543b382ceffcd78aff201a8a17d4b8955560d815dee1022306fe4755f424984`;
detached trust:
`76ac67cb21a77dfdb308f2aa52f25de9861159044ee6ce5eec0df19d7551f513`.
All85 entries/all2,879 runtime pins held; original factory independently rebuilt
inner wire/wrapper and all8 complete packets/bindings/short bootstraps byte-exact
using recorded gzip MTIME, with no ignored binding fields.

Fresh read-only VM/provider/SCM/MSI/update-state, ownership, identity and clock
reconciliation: **8/8 PASS**, normal native root exit0/wait0, complete streams,
no timeout. Native observer record hash:
`eb9021b61303731d9e995db35118c9f3b51513c3d8cf4b78748c432a8d0022f6`.
B maximum full command7,796 units including NUL, remote7,659, root325;
seq04 stdin452,088 bytes verified offline and never dispatched. Fresh read-only
packets used sealed stdin on the dedicated Windows VM. Accepted runtime remains
unchanged, including isolated Python3.12 and the historical management Python
and dependencies; local tests/packet checks used Python3.12 / PowerShell5.1.

A's separate failure review hash:
`4c90cdc1c31477e1a424cab0e4ac270ef18da137e44553dfcbbadc920e3731a3`.
A remains UNKNOWN; B PASS does not establish its RCA or execution acceptance.

## Final read-only admission gate

Status: **READY_REQUIRES_SEPARATE_AUTHORIZATION**. This is protocol/read-only readiness; seq04 remains unauthorized.

Final gate SHA-256: `811bce54592e53c00232932cedc9deb9ce01986529023f14a5ebc67ddbe1641d`.

Independent complete admission review: `de2f74ea84a44e6535b6b606fe9bdd560c6d0ea8f36e0ce11fdd199bf22f7a0f`.

Final preservation artifact: `79c92ca39b51552541c202a7628a5fbf6501165b8715d071a023cbd27df61e82`; preservation digest remains `49b3707bd72a001c730c77c39a0608d204a13a80c83bb58c812120cabb3a3ac1`. Old claims3; recovery slotABSENT; alloriginalfourcheckpoints/seal/deadlines/receipts/Facts/baseline/snapshot unchanged. No execution claims/capsule/authority/receipt04 created, no runtime/agent/MSI/Setup/marker/restore/rollout action.

Gate checked UTC: `2026-10-12T06:27:43.942206+00:00`; authorization deadline must not exceed `2026-10-12T06:47:43.942206+00:00`. An expired gate requires a new read-only preparation/review; never extend its deadlines or edit evidence.

The following is a **text template only**, not an authorization record. A later separate actual human message must exactly match this canonical format while sufficient full execution budget remains:

```text
TASK13_RECOVERY_EXECUTE_V1 {"allowed_seq":4,"continuation_id":"1795f237-94e0-42ca-a4e2-72696bc7f585","expires_utc":"2026-10-12T06:47:43.942206+00:00","gate_sha256":"811bce54592e53c00232932cedc9deb9ce01986529023f14a5ebc67ddbe1641d","implementation_sha":"ed29d24d7b43bae7e96eb5186227f4f3809e66dc","protocol_source_sha256":"c3c1f0823e22529b6fc67924af546ad716c640ad826ae7cbc6edac38a69ed5ba"}
```

After separate human authorization: prepare a new execution closure binding that actual app-session record, independently review its exact source/runtime/grant/packet pins, then repeat fresh preclaim and immediately-before-dispatch checks. Refuse before new claims on missing authority, drift, stale state or insufficient budget. A successful read-only gate is not receipt04 or permission to run.

**STOP here.** No seq04 was launched. No mass rollout or runtime change.
