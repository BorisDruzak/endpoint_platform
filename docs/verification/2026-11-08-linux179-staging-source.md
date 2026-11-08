# Linux 179 sealed staging configuration: source gate

Status: source reviewed and POSIX-tested; immutable native build started. This
receipt does not assert a 179 installation, administrator connection or primary
promotion. The live canary still runs the original 156 packages at this checkpoint.

Commit: `23e2b037f12f5b72474cc18401bd981403362381`

Message: `fix(linux): bind native updates to approved staging configuration`

## Problem and behavior

VM 107 is explicitly retained on staging. Its Core 156 unit uses the canonical
root-owned `/etc/systemd/system/endpoint-agent.service.d/staging.conf`. Signed 178
refuses every drop-in before native invocation, so it cannot qualify this selected
source. Its media and immutable staging source row are preserved.

The 179 correction accepts only that exact Core staging configuration: 215 LF
bytes, root:root 0644, regular single-link file, safe root-owned ancestors,
the four explicit operation-bound markers and matching loaded systemd values.
`NeedDaemonReload` must be `no`. Production, foreign fragments, extra drop-ins,
different directives and unsafe/replaced filesystem nodes remain refused.

All native-unit configurations are captured before ready invalidation or stopping
anything, including initially inactive units. Descriptor-pinned file/ancestor
identity, bytes and security are checked through preparation and recovery.
Arbitrary fragment text and loaded Environment values are retained only as
digests, never as raw credential-bearing values in receipts. Changed configuration
cannot cause RPM invocation or restoration of an externally changed service.
An uncertain possible-invocation boundary retains exclusive recovery ownership.

Setup-to-source binding now applies to every modern verified source. The only
exception is the exact historical 156 digest/NEVRA/source/manifest/publisher,
optionally paired with its exact Sensor. A package merely declaring 156 cannot
bypass modern binding. Runtime, freezer, retained Setup, RPM builder, manifest,
kit and dispatcher consistently target 179; independent Support remains 1.0.0.

## Files in the source commit

- `pc_agent/platform/linux/installation_configuration.py`
- `pc_agent/platform/linux/installation_coordinator.py`
- `pc_agent/platform/linux/installation_lifecycle.py`
- `pc_agent/version.py`
- `packaging/alt/build-rpm.sh`
- `tools/build_alt_native_kit.py`
- `tools/build_alt_pilot_kit.py`
- `tools/build_linux_native_manifest.py`
- `tools/release/freeze_linux_native_identity.py`
- `pc_agent/tests/test_linux_installation_configuration_file.py`
- `pc_agent/tests/test_linux_installation_coordinator.py`
- `pc_agent/tests/test_linux_native_executor_binding.py`
- `pc_agent/tests/test_linux_native_staging_configuration.py`
- `tests/build/test_linux_native_candidate.py`
- `tests/build/test_linux_native_manifest.py`
- `tests/native/test_linux_installation_native.py`

## Evidence and limits

The implementation recorded failing tests before each relevant correction:
approved staging admission, generalized executor/source binding, candidate 179
builders, cached authority, source-record consistency and mutation after durable
stop intent. Independent scoped specification/quality review found no actionable
defect; it also recomputed the 16-file manifest/diff hashes and ran 64 focused tests
plus 17 secure-reader tests, with 11 POSIX cases explicitly skipped on Windows.

Controller checks were split honestly: the initial Python 3.14 focused command had
180 passes, 25 skips and one qualified-Python guard failure. Only that target was
rechecked under the existing Python 3.12 interpreter and passed. After the final
stop-intent correction, the affected staging/coordinator suites passed 64 tests.
An unnecessary interrupted repeat was not counted as verification evidence.

Root then validated an exact 1938-file snapshot on the actual ALT Python 3.12.13
SDK, using the marked isolated native harness, synthetic units and its own RPM
database. The command selected these fourteen files:

```text
python -m pytest -q -ra --tb=short
  pc_agent/tests/test_linux_native_staging_configuration.py
  pc_agent/tests/test_linux_installation_configuration_file.py
  pc_agent/tests/test_linux_native_executor_binding.py
  pc_agent/tests/test_linux_installation_coordinator.py
  pc_agent/tests/test_linux_installation_lifecycle.py
  pc_agent/tests/test_linux_installation_notification.py
  pc_agent/tests/test_linux_installation_user_sessions.py
  tests/build/test_linux_native_candidate.py
  tests/build/test_linux_native_manifest.py
  tests/build/test_linux_native_verifier.py
  tests/packaging/test_linux_support_freeze.py
  tests/packaging/test_alt_rpm_contract.py
  tests/packaging/test_alt_pilot_kit.py
  tests/native/test_linux_installation_native.py
```

The first invocation returned 203 passes, one built-RPM skip and three harness
environment failures: two archive tests lacked Git metadata in the snapshot;
the unrelated OTA-baseline fixture inherited 0077 rather than its expected 0022
umask. No source fix was made for these failures. Root proved that the three
archive inputs matched existing committed Git objects, supplied that read-only
Git directory, and reran only the three failed tests under 0022: all three passed.
Thus the reconciled POSIX result is **206 passed, 1 skipped across split runs**,
not a single green command. The remaining actual-built-RPM probe is deferred to
the new native build. Three warnings concern unused asyncio settings in the
minimal isolated pytest environment.

All 11 real root/POSIX descriptor/ownership cases ran successfully, including
same-byte inode replacement during preparing recovery. A further read-only probe
called the actual backend configuration reader on all five current VM 107 units.
It accepted the existing exact staging file and the loaded cache, with no native
invocation or unit mutation. Core PID 1061 and restart count 0 remained unchanged.

Root independently compared every committed file with the tested snapshot:
all 1938 byte hashes matched. Review diff SHA256:
`4acb75cc62e11e9d6fab89c3db260982c0e506c74b52cea7822abaec65472a11`.
Test snapshot SHA256:
`79640c7475d54b6f01468079ff1594f4a81efb77d4fbf6bd12899c6a4b108cee`.
`bash -n packaging/alt/build-rpm.sh`, working/staged diff checks and explicit
task-file staging checks passed. The source commit includes exactly the 16 files
above. The operator proof is `task6-179-committed-source-proof.json` under
`C:/endpoint-platform-wix-build/linux178-native/`.

Root imported that commit into the clean canonical native build clone and started
`endpoint-linux179-build-final-23e2b037.service`. Original 156 source, installed
client, AD/SSSD, user session, Windows 177 distribution and Linux 156 primary remain
preserved. Frozen 179 signatures, exact-source publication and the full live
installation/telemetry/independent-access sequence remain subsequent gates.
