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
