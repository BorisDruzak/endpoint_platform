#27 Power checkpoint reset loop

Read-only server evidence showed reset6611to6776 within08:04to08:07UTC,
DEGRADED/loss0. Server copies client counters; it does not sum repeated delivery.
Today's native boot06:10:35 and shutdown report06:10:37 had already reached the
server. Historical missing Oct21 boot alone could not explain the current loop.
The earlier authorized256MiB System-log maximum increase succeeded Nov5; no
reboot/log clear/configuration repair was performed in this investigation.

Root read existing Power DB/WAL and System.evtx through already available domain
SMB, copying only to protected local evidence storage. No workstation command,
preparation, service restart, Task registration, source checkpoint/counter update
or log mutation occurred. SQLite copy integrity passed. Saved checkpoint256200
anchor a70931f4f02f48a831492c3e046d5aa44ab2217366f039503f2b8e904c95b017 maps
to Kernel-Power41 at exact XML2026-11-06T06:10:37.7190788Z. System bounds197849to
275552 contain it. The capture also has older CProCtrl292 with same numeric ID.
Both record chunks have valid CRCs. Non-atomic live-copy header/tail differences
prevent an OS-corruption or provider-blame conclusion; no OS cleanup is justified.

Actual original native reader selected the unrelated first forward full-System
match, rejected the checkpoint anchor and replayed3rows/2events. Projection
returned exactly the same checkpoint. Three repetitions reproduced the reset
loop. Scoping validation to the same Power whitelist fixed that false mismatch.

Reviewed fix d4774f78b3a5e1ea356936171bbc46fbcb5fadc4 reads at most2anchor
candidates. An unrelated provider cannot invalidate the Power anchor; conflicting
Power identities retain checkpoint/history/counters and reportDEGRADED without
reset/replay. Notifications pause until continuity is provable. Real missing,
mismatch,out-of-range and source loss behavior remains conservative. Native
handles close on every path; original7digit XML anchor timestamps are preserved.

Source tests:91agentPower tests;131combined agent/server Power tests with one
existing Authlib warning; independent reviewer25fallback tests. A stale migration
head assertion was fixed separately5d82d6d, retaining single-head and exact Power
DDL checks with no migration run. Native captured-EVTX proof:4READY polls,
zeroevents/reset/loss, unchanged checkpoint, unchanged eventUUIDs and captureSHA.
All proof files remain local under .superpowers/sdd/2026-11-06-power-stream-anchor
and protected C:\Temp\endpoint-setup165-20261105\power27-capture-20261106T0808.

171 is immutable and retains the old Power reader. Full172 will include both
this repair and d5cfb0d Foundation execution metadata repair. Live27 acceptance
must show freshREADY, stable durable reset count, no duplicate history, native0,
private preservation and fresh active UserSensor; do not rewrite history/counters
or qualify a different artifact. Enrollment165 and fleet3/disabled/max2 unchanged.


## Live172 receipt

Console assignmentdf7a2b50-5d2d-43b5-a00e-87551b769d99 accepted native0 at08:45:05.429953Z, exact Core/Foundation172 with181.898sec/6samples/1Sensor and private4. Fresh Power samples changed toREADY while durable reset8689/loss0 and all36original server facts remained unchanged. UserSensor/Activity and observer107 are fresh. No manual workstation preparation/restart/reboot/log operation was used for172. Source170 was qualified and fleet policy5/all_active/max2 enabled only after exact172 acceptance; see the172 verification/release records for later rollout. Earlier171/disabled statements above describe the preserved investigation checkpoint.
