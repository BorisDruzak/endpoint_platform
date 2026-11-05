# Windows power rollover repair implementation plan

**Goal:** Restore current power monitoring after native boot evidence rolls out,
and verify the corrected Core update through Endpoint before wider Windows waves.

**Architecture:** Preserve System event provenance and add bounded, read-only WMI
current-boot context inside the existing killable worker. No new server contract
or Foundation build. Reuse this clean, suitable production worktree.

**Spec:** ../specs/2026-11-05-power-rollover-design.md

## Tasks

- [x] Diagnose both devices; preserve the actual disconnected-session result and
  read-only System log metadata. Increase only101.27's System maximum, without reboot.
- [x] Add regression tests in pc_agent/tests/power/test_windows_boot_fallback.py;
  run RED before changes. Cover rollover, no synthetic startup, old-boot rejection,
  record-ID reuse, WMI validation/failure, current notifications and primary-path stability.
- [ ] Implement the smallest reader/projection fix in
  pc_agent/platform/windows/power_events.py. Run GREEN and relevant full suites.
- [ ] Review exact impact, diff and release compatibility. Commit the fix and new
  Core version atomically. Build Windows Core from that exact committed source;
  retain signed observer input and immutable158/163 artifacts.
- [ ] Publish through canonical update registration, verify actual downloaded ZIP
  and hashes, then update101.27 and101.187 through Endpoint. Verify applied state,
  unchanged Foundation158/private identity, selected Core, fresh WSS/sensor/activity,
  current power source and stable observation; no workstation bootstrap preparation.
- [ ] After canaries pass, run bounded waves on compatible active Windows agents;
  preserve other platforms, conflicting operations and disconnected sources.
- [ ] Record actual outcomes/limits and immutable release metadata; complete review
  and relevant checks before committing acceptance. Do not claim unrun native Setup.

## Review focus

- Recreated logs reuse record numbers: do not collapse distinct native facts.
- WMI boot time cannot label older retained boots or manufacture startup evidence.
- Source READY after recovery must preserve explicit historical gaps/counters.
- Optional WMI failures remain bounded and never interrupt main agent transport.
- Existing signed observer/bootstrap and Foundation compatibility remain intact.

## Execution ledger

-06:08Z:101.187 WTS2 Disconnected→Active console; existing sensor PID10180 retained.
-06:14Z: all four postcheck health/session collections completed; fresh sensor data.
-101.27 System metadata confirms rollover. Generic console-as-SCM probes did not
  yield verified execution; do not treat1053 as a repair receipt. Temporary service
  cleanup and proper administrative execution are required before claiming resize.
-06:23:46Z: proper Microsoft-signed PsExec administrative execution completed the
  guarded owner/device-specific resize20→256MiB. Full XML comparison proves only
  maxSize changed. Independent06:33Z query confirms256MiB, no temporary services
  or wevtutil processes; last boot remains21Oct. No reboot or GPO change.
- Ruling: issue a Windows Core164 patch with minimum Foundation158, leaving native
  Foundation158 and historical156/158/163 artifacts immutable. The user delegated
  the release-format choice; native service changes are unnecessary for this bug.
- Initial regression RED3 failed/3 passed, then80 power tests GREEN on Python3.12.
- Independent code review found fallback-to-native page identity instability,
  derived-time attribution of pre-boot records, and UTC overflow. Five new cases
  reproduced them RED. Fix pass keeps fallback provenance through its actual row
  boundary, accounts for native-query races, validates both timestamps, and treats
  overflow as missing optional evidence. No second reviewer pass is required.
- Ruling: reject extreme UTC-conversion overflow as part of the WMI validity
  boundary, rather than leave it a cosmetic deferred minor. Otherwise malformed
  optional evidence would fail the entire native worker page.
- Ruling: dependency-isolation tests use a source-equivalent unsigned fixture
  explicitly labeled metadata-only; release build still requires the actual
  separately Authenticode-verified observer. This removes an accidental private
  operator-environment dependency without treating the fixture as trusted media.
- Test environment: initial default Python3.14 run was stopped (project pins3.12).
  First Python3.12 full collection lacked Authlib; isolated test-extra supplies
  pinned Authlib1.9.1/ joserfc1.8.0 without modifying shared build/test environments.
  Previous golden fixture161 is updated together with the164 version bump.
