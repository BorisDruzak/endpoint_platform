# Task 14 report — Windows Device Context collectors

## Delivered

- Added Windows platform collectors for stable system/hardware facts, bounded
  volume storage, interface facts, static agent software, and MachineGuid-based
  machine identity.
- Kept `machine_id` outside every Device Context payload.  The Windows identity
  helper uses the existing MachineGuid UUID derivation and durable fallback;
  hostname and IP address are never inputs.
- Routed `baseline_v1`, `health_v1`, `network_v1`, and `diagnostic_v1` through
  the existing fixed capability registry when the probe declares Windows.
- Windows health intentionally returns no service inventory. Diagnostics use
  only the fixed `tasklist /FO CSV /NH` command with a two-second timeout and a
  32 KiB output cap. No WMI, PowerShell, host access, or service probing was
  added.
- Added sanitized golden envelopes covering all four profile contracts and
  baseline privacy boundaries.

## TDD evidence

1. `python -m pytest pc_agent/tests/windows -q` initially failed during
   collection because `pc_agent.platform.windows.identity` did not exist.
2. Implemented the smallest Windows collector surface and profile dispatch.
3. Focused profile and existing ALT schema tests then passed.

## Verification

- `python -m pytest pc_agent/tests/windows pc_agent/tests/context pc_agent/tests/test_device_fingerprint_agent.py -q`
  - `128 passed, 3 skipped`
- `python -m compileall -q pc_agent/context_profiles pc_agent/platform/windows`
  - passed
- `python -m ruff check pc_agent/context_profiles pc_agent/platform/windows pc_agent/tests/windows`
  - passed
- Local Windows `SystemProbe` smoke executed all four registry capabilities:
  `baseline_v1`, `health_v1`, `network_v1`, and `diagnostic_v1`.
- `python -m pytest pc_agent/tests -q` could not collect two unrelated existing
  suites because this worktree has no `scripts.build_module_zip` or
  `scripts.register_support_modules` modules.

## Concerns

- The native network fallback intentionally reports an unknown default route
  when a probe does not supply one; it does not run a locale-sensitive command
  or a connectivity probe. The profile remains schema-valid and interface facts
  stay bounded.
