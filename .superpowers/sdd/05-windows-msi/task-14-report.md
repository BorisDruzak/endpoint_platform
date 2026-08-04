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

## Fix round 1 — Windows identity override precedence

- Root cause: `stable_machine_identity()` delegated to the generic resolver,
  which intentionally processes `PC_AGENT_MACHINE_ID` before MachineGuid. An
  IP address or hostname in that generic override became an `env_seed` device
  identity.
- Fix: the Windows helper now invokes the existing MachineGuid resolver
  directly, then its existing durable fallback. It never consumes
  `PC_AGENT_MACHINE_ID`.
- TDD evidence: the new IP-override and hostname-override regression tests
  initially failed with `env_seed`; after the one-line resolver-order change,
  `pc_agent/tests/windows/test_identity.py` reported `4 passed`.

## Packaging integration — versioned initial-runtime transition

- Root cause: the immutable `initial-runtime.json` remains pinned to `3.1.76`.
  Task 14 changed five of its reviewed Device Context sources and introduced
  four Windows collector modules, so a routine build correctly rejected the
  changed `baseline.py` hash.
- Preserved the `3.1.76` baseline and added the explicitly approved
  `initial-runtime-3.1.77.json` transition with a new component GUID
  `E6799EB3-DA89-43D9-A1F6-6B60E03203E9`. `AGENT_VERSION` is now `3.1.77`.
  The transition pins the complete staged runtime tree: 2,493 files and
  SHA-256 `eb3e763fd241fb327467ae5b254f23c7de99c3f95e141ab8e258f4c2cd5f932f`.
- TDD RED: the checked-in transition regression initially failed because the
  manifest did not exist. Source-contract validation then passed only with
  both transition approvals. A second RED showed WiX 4 rejected concatenated
  `-dName=value` switches; the builder now passes each define as separate
  `-d`, `Name=value` arguments. A third RED showed WiX 4 rejects
  `File/@NeverOverwrite`; it is now the correct `Component/@NeverOverwrite`
  MSI bit.
- The documented build command now explicitly names the reviewed transition
  manifest and both approval switches. The `3.1.76` baseline is not replaced
  or re-pinned.
- Exact approved build reached WiX 4.0.6 after the local Util extension was
  added. WiX parsed and bound all sources but stopped in its cabinet writer
  with `WIX0001 System.IO.IOException: The pipe is being closed`; this is an
  external WiX native cabinet failure after staging and authoring validation,
  not an MSI source/manifest validation failure. No system service or host was
  modified.

## Deterministic payload and short WiX build root

- Root cause: unpinned `PYTHONHASHSEED` made PyInstaller emit different byte
  order for identical entries in `_internal/base_library.zip`. The complete
  staged runtime hash therefore changed between clean builds, even though all
  extracted module contents matched. WiX's native cabinet writer also failed
  when generated source paths exceeded the Windows path limit in this long
  worktree.
- The builder now pins `PYTHONHASHSEED=0`. The 3.1.77 manifest is schema 3 and
  records that seed as part of the frozen toolchain identity; immutable schema
  2 baseline 3.1.76 remains valid and unchanged. The approved deterministic
  artifact identity is 2,493 files with SHA-256
  `e8508f45488421f847022e7f1d8021967824675f0f49865940fea544be5845bd`.
- PyInstaller continues to build from the ordinary repository source path.
  WiX staging/output/generated payload use the dedicated short default
  `C:\endpoint-platform-wix-build\Release-x64`, or a validated explicit
  `-WixBuildRoot`. Volume roots, repository-internal paths, and reparse points
  are rejected before cleanup.
- TDD RED/GREEN: added contract tests for hash-seed pinning, schema-3 seed
  enforcement, safe short-root wiring, and discarded COM inspection outputs.
  They initially failed; then `32 passed` after the minimal implementation.
- Exact clean build evidence: the ordinary C-source command with the approved
  3.1.77 manifest exited 0, created
  `C:\endpoint-platform-wix-build\Release-x64\output\EndpointAgent-3.1.77-x64.msi`
  (83,788,172 bytes), and wrote inspection rows for 2,498 files, 2,501
  components, two services, and 11 properties. No service or host was changed.
