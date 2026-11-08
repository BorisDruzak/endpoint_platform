# Linux 180 bounded Support startup retry: source gate

Source: `26864c50313a03dd9cfac03a9559b9fbce1fa74f`.
Commit: `fix(linux): retry support startup after delayed gateway authorization`.
Status: actual ALT isolated startup tests passed, but a separate retained-Setup
version guard blocks 180 before installation. **Not installed, qualified or
promoted.** A distinct 181 candidate corrects that guard.

The actual 179 canary exposed a startup race between an enabled HTTPS policy and
the gateway's independently refreshed authorization. Linux Support now retries
only a confirmed dead initial SSH master during a **15-second activation window**
bounded by the original BOOTTIME expiry. Each attempt gets a decreasing cgroup
lifetime. The local SSH daemon starts once; retry stops only the owned tunnel
unit, confirms it stopped, and checks any stale control socket before removal.
Positive status still requires native forwarding acknowledgement and the same
kernel-verified master/socket identity. Server eligibility, expiry, revocation,
principal validation, keys, TLS and host verification are unchanged.

A live master whose control socket cannot be verified fails closed. The initial
scoped review identified that the previous generic timeout classification could
restart such a live master. A deterministic test reproduced two launches before
the correction; the amended classification now permits only one and retains no
acknowledgement or positive receipt. The narrow re-review found that issue
addressed and no new issue in the two-file fix. Original review and correction
evidence remain retained with the task ledger.

The independent Support wire/component version remains 1.0.0. Its changed bytes
are bound to the new exact native source. Frozen component identities, manifest,
RPM builder, kit, dispatcher and current-candidate tests target 3.2.180. Root's
subsequent pre-install source check found a separate hardcoded 179 comparison in
`retain_executor`; the reviewed scope and tests had missed that entry path.
Existing signed 178/179/180 packages and source rows remain immutable.

## Verification

Root's final pinned Python 3.12.14 command selected these nine files:

```text
pc_agent/tests/linux/test_support_access.py
pc_agent/tests/linux/test_support_access_native.py
pc_agent/tests/linux/test_support_access_service.py
tests/server/test_linux_support_whole_seams.py
tests/contracts/test_linux_support_lifecycle.py
tests/packaging/test_linux_support_freeze.py
tests/build/test_linux_native_candidate.py
tests/build/test_linux_native_manifest.py
tests/packaging/test_alt_rpm_contract.py
```

`python -m pytest -q` with those paths returned **125 passed, 4 skipped**, with
one existing Authlib deprecation warning. The skips require actual POSIX ownership
or a built RPM. Separate RED evidence includes the two initial startup failures,
the live-master regression, and four new-candidate binding failures before their
corrections. Shell syntax, Python compilation and working/staged diff checks
passed. All 12 staged files matched the independently reviewed byte hashes.
GitNexus was unavailable; source, tests and the scoped dependency boundary were
checked directly. No cross-repository HTTP contract changed.

The exact committed source was imported into the clean ALT build clone using a
verified incremental Git bundle. On ALT Python 3.12.13, eight focused source and
packaging/native files returned **109 passed, 1 skipped**; three warnings concern
unused asyncio options in the isolated minimal pytest environment. The one skip
requires the subsequently built RPM. These eight files comprise the three agent
Support suites, candidate/manifest suites, ALT RPM/Support freezer suites and
`tests/native/test_linux_installation_native.py`.

The actual root-only disposable harness then passed all 15 checks, using systemd
258.9 and installed OpenSSH. It checked isolated key-only root SSH, expiry killing
a detached session, closed expired listener, strict mux acknowledgement, rejected
forwarding, master death, absent-master refusal and private-node protections.
The new regression first observed actual public-key rejection, delayed its own
temporary gateway key by six seconds, then exercised the production start loop:
**six attempts, successful forwarding after 6.632 seconds, real forwarded bytes**.
Per-attempt lifetimes decreased from 26 to 20 seconds under the same original
30-second deadline. All harness units stopped, adapters were restored, and its
temporary public authorization directory was removed. No real product unit,
ordinary SSH configuration or external gateway was used by this harness.

The combined ALT command receipts were `[0, 0]` at 11:42:04.791535Z. Installed
Core PID 494365 and updater PID 0 were unchanged, and the source clone stayed
clean. These results qualify the isolated regression, not installed service
access. The exact 180 build started afterwards in a new output directory.

## Frozen media and pre-install blocker

The actual build completed at 11:44:24.217141Z, commands `[0, 0]`, source clone
clean and Core/updater PIDs unchanged. The final built-RPM opt-in test subsequently
passed: **110 POSIX passes across split runs**, rather than one combined run.
Both native RPM signatures, complete source closure and Setup digest were checked
on ALT and independently on staging. The kit archive and manifest were signed
and verified with the existing pinned publisher. Staging registered exact source
`a8aaf525-3f2e-4807-be4e-c299a3772eff` at 11:51:26.502597Z using the mandatory
real native verifier. See the matching 180 candidate record for immutable hashes.

Before any 180 invocation, Root found that `retain_executor` still compared the
embedded Setup identity with literal `3.2.179`. An actual retained 180 image would
therefore fail before RPM. **No 180 native transaction or bootstrap failure is
invented:** neither installation nor that blocked invocation was performed.
The 181 correction will compare the frozen identity against the same build's
tracked `AGENT_VERSION`, retaining exact component/source/digest binding. A test
must exercise the real retained-executor branch, including the current version
being accepted and stale 179 being rejected. Frozen retained-entry smoke testing
will precede the next actual native operation.

## Files in the source commit

- `pc_agent/platform/linux/support_access_native.py`
- `pc_agent/tests/linux/test_support_access_native.py`
- `pc_agent/tests/linux/support_access_native_harness.py`
- `pc_agent/version.py`
- `packaging/alt/build-rpm.sh`
- `tools/build_alt_native_kit.py`
- `tools/build_alt_pilot_kit.py`
- `tools/build_linux_native_manifest.py`
- `tools/release/freeze_linux_native_identity.py`
- `tests/build/test_linux_native_candidate.py`
- `tests/build/test_linux_native_manifest.py`
- `tests/native/test_linux_installation_native.py`
