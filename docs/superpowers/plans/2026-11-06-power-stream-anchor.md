# Power stream checkpoint anchor implementation plan

> **For agentic workers:** Use TDD for the independent Power reader repair;
> parent continues the frozen171 installer canary. Do not modify release/build
> files, deploy, commit or access workstations from the implementation subtask.

**Goal:** Stop false reset/replay loops when an unrelated System provider reuses
the numeric EventRecordID of the saved Power checkpoint.

**Spec/evidence:** Device27's checkpoint256200 anchors Kernel-Power41 at exact
XML time2026-11-06T06:10:37.7190788Z. A protected read-only System.evtx capture
contains an older CProCtrl292 with the same numeric ID. Existing forward
whole-System lookup selects the unrelated record. Actual native reader/projector
against that capture reproduced three reset/replay cycles with identical final
checkpoint; restricting only anchor validation to the existing Power whitelist
produced three stable no-reset/no-event reads. Details and forensic limits:
`C:\Temp\endpoint-setup165-20261105\power27-readonly-findings.md`.

**Architecture:** Validate anchors in the same whitelisted stream that created
them. Bound native candidate reads and reject conflicting/overflow Power
identities conservatively, without repeatedly replaying the same page. Preserve
checkpoint and DEGRADED on ambiguity; preserve genuine missing/mismatch/range
reset recovery. No new server contract, fabricated boot event or counter reset.

**Tech stack:** Existing Windows Power reader, CPython3.12/pywin32 311 and tests.
Context7 and native API documentation already consulted in the parent workflow.
GitNexus baseline was consulted earlier; tools currently unavailable, so verify
this narrow local adapter path against current source/tests.

## Global constraints

- No clearing/rebuilding Windows logs, reboot, service restart, workstation
  preparation or SQLite mutation on27. Existing snapshots are evidence only.
- No changes to stored counters, coverage, event identities or server history.
- Preserve exact seven-digit original XML timestamp in record anchors.
- Do not claim OS corruption, provider blame or an atomic snapshot: the live
  EVTX copy is non-atomic, although duplicate record chunks have valid CRCs.
- Frozen171 excludes this repair. Carry a reviewed fix into a distinct full172
  after171's installer canary; do not overwrite171 binding or signed bytes.
- Fleet3 stays disabled/max2 until exact final-artifact canaries and source
  qualifications. UserSensor, Power health and native receipt are separate gates.

## Tasks

- [x] Write RED tests: unrelated same-ID provider preceding matching Power;
  conflicting same-ID Power anchors; bounded-candidate overflow; genuine missing/
  mismatch/out-of-range recovery; exact timestamp preservation; repeated stable
  polls and unchanged event identity/history. Implement the smallest adapter
  change and run related Power tests. Save a local native EVTX regression proof
  with no workstation writes. Parent reviews and commits only related files.
- [ ] Rebuild/sign distinct full172, verify actual bytes/functions, and canary
  through Endpoint.27 must report several fresh READY samples with stable durable
  reset count and no duplicate history; installation needs native0/private/fresh
  user proof. Qualify exact sources before enabling all-active/max2 waves.


## Source verification

Fix d4774f78b3a5e1ea356936171bbc46fbcb5fadc4; independent review found no
remaining issue and independently ran25fallback tests. Agent Power91passed;
combined agent/server Power131passed14.84seconds with the pre-existing Authlib
warning. An unrelated stale schema-head assertion was reproduced RED and fixed
separately in5d82d6db7ff72a572eb33b8618e563bd61b8c3bc; single-head and exact
Power DDL assertions remain, no migration/database change was performed.

Actual Win32 reader against immutable captured EVTX produced4READY polls,
zeroevents/reset/loss, unchanged checkpoint and original eventUUIDs. Capture
SHA6596adc263ae1dd35fa12b34fe49e3932660c06bb5cd87f8a8e6159fc07b5e77 stayed
unchanged. This is local fixture acceptance;27's live acceptance requires172.
