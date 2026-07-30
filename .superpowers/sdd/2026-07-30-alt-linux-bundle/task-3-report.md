# Task 3 Report: isolated ALT bundle Linux harness

## Plan

1. Add a wrapper test that requires the new Linux harness and skips only its
   shell execution on non-Linux hosts.
2. Record the failing wrapper test while the harness is absent.
3. Add a `mktemp -d` harness that rewrites every installer destination below
   its temporary root and stubs service/account commands locally.
4. Verify the Python wrapper suite and shell syntax locally; run the full
   harness with `sudo` on the dedicated Linux test host before any remote
   installation work.

## TDD record

RED was observed before adding the harness:

```text
python -m pytest tests/deploy/test_alt_agent_bundle_install.py::test_linux_harness_is_present_for_the_bundle_installation_scenarios -q
FAILED: missing isolated ALT bundle Linux harness
```

## Delivered coverage

`tests/deploy/verify_alt_agent_bundle_linux_harness.sh` copies the installer,
config, and service unit into a fresh temporary root for every case. It patches
only the installer destinations into that root. Its `systemctl` and `useradd`
stand-ins are located inside the same root; no host service, account, or fixed
installer directory is changed.

The harness runs these scenarios: valid installation, manifest digest mismatch,
bundle symlink, a bundle missing `pc_agent/_internal`, activation-failure
rollback to the previous selector, and a second identical installation. It
captures installer diagnostics and prints only per-case statuses plus a bundle
manifest SHA-256 digest.

## Verification

- `bash -n tests/deploy/verify_alt_agent_bundle_linux_harness.sh` succeeded.
- The targeted pytest command is recorded in the final verification output.
- Full harness execution is intentionally pending a Linux environment. This
  Windows workstation has no installed WSL distribution and no local Docker
  runtime. The required pre-install command on the permitted Linux test host
  is:

```text
sudo bash tests/deploy/verify_alt_agent_bundle_linux_harness.sh deploy/agent/alt/install-endpoint-agent.sh
```

No test host, production host, remote, or persistent credential was accessed.

## Review round 1 correction

RED was observed before the correction:

```text
python -m pytest tests/deploy/test_alt_agent_bundle_install.py::test_linux_harness_proves_isolation_and_reaches_the_injected_restart_failure -q
FAILED: missing assert_isolated_installer_copy
```

The installer-copy rewrite now also covers `/opt/.endpoint-agent-stage`, every
hard-coded `require_trusted_root_parent` path, the systemd unit destination,
and `login.defs`. Before any scenario runs, the harness rejects a copied
installer containing any unrewritten live-root install, staging, or fixed-parent
path. It also snapshots those live locations before valid, rollback, and
idempotent cases and requires the snapshot to remain unchanged afterwards.

The rollback case now clears the service stub log after the first successful
install and requires the injected run to contain exactly
`restart endpoint-agent.service`; a generic early installation failure cannot
satisfy the rollback assertion.

## Review round 2 correction: archive input contract

The Linux execution failure was pre-scenario: the copied installer expects
`default-config.yaml` and `endpoint-agent.service` immediately beside it, but
the transferred input contained only the installer. The harness now validates
the installer plus both adjacent regular, non-symlinked LF assets before any
root check or temporary scenario root. A missing asset exits with status 2 and
the safe message `missing required harness asset: <filename>`.

Transfer the harness and all three installer inputs as one LF Git archive; do
not transfer the installer alone:

```text
git archive --format=tar --prefix=alt-linux-harness/ HEAD \
  deploy/agent/alt/install-endpoint-agent.sh \
  deploy/agent/alt/default-config.yaml \
  deploy/agent/alt/endpoint-agent.service \
  tests/deploy/verify_alt_agent_bundle_linux_harness.sh > alt-linux-harness.tar
sha256sum alt-linux-harness.tar
tar -xf alt-linux-harness.tar
sudo bash alt-linux-harness/tests/deploy/verify_alt_agent_bundle_linux_harness.sh \
  alt-linux-harness/deploy/agent/alt/install-endpoint-agent.sh
```

The archive preserves the required adjacency and the harness rejects CRLF
inputs before executing any case. The command neither needs nor carries a
credential or provisioning handoff.

## Review round 3 diagnosis and correction

The exact-LF Linux archive reached the harness input preflight but every case
then failed before the installer ran. Local reproduction of the rewrite and
isolation checks identified the common cause: `assert_isolated_installer_copy`
used an unanchored `/etc/login.defs` substring check. The correctly rewritten
temporary path (`<mktemp-root>/etc/login.defs`) contains that substring, so the
harness rejected every copied installer before any scenario invocation.

RED was recorded for both regressions:

```text
python -m pytest tests/deploy/test_alt_agent_bundle_install.py::test_linux_harness_reports_a_bounded_redacted_valid_install_failure -q
FAILED: missing emit_safe_failure_diagnostic

python -m pytest tests/deploy/test_alt_agent_bundle_install.py::test_linux_harness_does_not_mistake_its_temp_login_defs_for_a_live_path -q
FAILED: unanchored /etc/login.defs check present
```

The live `login.defs` check is now anchored to an absolute path boundary, so it
still rejects an actual `/etc/login.defs` reference but accepts the temporary
root's rewritten file. Isolation and archive-input preflight are otherwise
unchanged.

For any future valid-case installer failure, the harness reads at most 8 KiB of
the private captured log and emits only a fixed failure category plus one fixed
safe message token (for example `installer-fixed-parent` and
`fixed_destination_parent`). It never prints captured output, input paths, CA
data, handoff material, claims, or credentials. This distinguishes rewritten
path, account-stub, service-activation, bundle-verification, staging, missing
path, permission, and unknown failures without expanding diagnostic exposure.

## Review round 4 correction

The copied-installer live-root guard now uses a lexical absolute-path detector
rather than whitespace matching. It rejects the supported live installer roots
when used bare, quoted, in an assignment, or in shell redirection syntax; it
continues to allow the corresponding paths underneath the temporary harness
root. Wrapper tests execute this detector against those four fixture forms.

The safe diagnostic no longer uses `read_bytes()`. It opens the private
captured log in binary mode and reads at most 8192 bytes. Its oversized-fixture
test verifies that the output remains the fixed safe category/message token and
does not contain the fixture's claim-like suffix. No captured bytes are printed.
