# Linux update baseline after Windows177 acceptance

## Request and current boundary

The user requested starting the Linux client update after completing Windows
testing and stabilization. Windows177 native acceptance, six-device available
cohort acceptance and the final fresh recheck are recorded in
[the Windows receipt](2026-11-07-test120-installation-lifecycle177.md).

Linux preparation started from clean commit
`5cc72cda04e545556baed197c8c890ffef1198aa`. No Linux package was built,
installed, promoted or fleet-assigned during this baseline. Existing Windows
policy12 and the published ALT156 bytes were preserved.

## Current published Linux bytes

The canonical record still identifies ALT11 x86_64 version3.2.156, runtime
`6ed41cd01d494e46111a452c2ae3a844f723175b`, kit metadata
`d007064792caa5f3b94d911c73b13214913a230c`.

Both public files were freshly read over CA- and hostname-verified HTTPS from
`endpoint.sosnadmin.local`, with redirects rejected. Actual bytes matched:

| File | Bytes | SHA-256 |
|---|---:|---|
| endpoint-alt-pilot-3.2.156-1.manifest.json | 3978 | c74f20dbb15d92808e5b11da582cf1ae73c1760cfdd71c7686298a069f71a004 |
| endpoint-alt-pilot-3.2.156-1.tar.gz | 50813618 | 071720bbda4c1fc81152a1fd4fa004c02b096f9ecf162bac996b2c0dd746f2c9 |

This refresh verifies published byte identity and TLS. Native RPM and detached
signature verification were not rerun in this baseline.

## Source and test findings

The source kit builder currently pins a distinct historical157 candidate;
packaging documentation also contains127 examples. Neither supersedes the
canonical156 release. Future packaging must explicitly bind new immutable
source, native RPM identities, signatures and actual served bytes.

The current installation event contract requires Windows ProductCode and MSI
SHA-256. Support policy/runtime currently select a Windows administrator.
Linux reserve access and native RPM removal facts therefore require an explicit
platform-compatible design and tests; changing a version number does not supply
these features. The user's intended scope was asked separately: common client
fixes first, or also independent access and installation lifecycle parity.

The following existing checks ran in the Windows development environment:

```text
python -m pytest pc_agent/tests/linux pc_agent/tests/context/test_alt_baseline.py pc_agent/tests/context/test_alt_inventory.py pc_agent/tests/context/test_linux_identity.py pc_agent/tests/context/test_linux_sessions.py pc_agent/tests/runtime/test_linux_user_sensor.py pc_agent/tests/runtime/test_linux_user_sensor_cancellation.py pc_agent/tests/runtime/test_linux_user_sensor_entry.py tests/packaging/test_alt_rpm_contract.py tests/packaging/test_alt_user_sensor_start.py tests/packaging/test_alt_pilot_kit.py tests/build/test_linux_headless_artifact.py -q --tb=short
```

Result: **137 passed,29 skipped in17.65seconds**. These are supplemental source
checks, not live RPM/systemd/KDE or native Linux acceptance.

## Live test-host availability

Strict existing-host-key SSH to the dedicated `test-agent-lin`,
`192.168.101.162:22`, timed out from the operator workstation. A separate bounded
TCP check from `endpoint-platform-server` returned `No route to host`.
Neither proves whether the PC is powered off or how its network failed.

The user was asked to restore this test host or identify another authorized
Linux test PC. No production workstation was substituted, and no host keys,
accounts, AD/SSSD state, services or firewall configuration were changed.

GitNexus MCP was unavailable in the session; the current committed source,
release records, packaging and tests were inspected directly. Live acceptance
and new publication remain outstanding.

## User follow-up and bounded rechecks

The user selected independent reserve access plus removal/reinstallation parity,
and reported the test PC powered on. Repeated strict SSH probes after that reply
still timed out; the server-side route points to ens18 but its neighbor entry for
162 was FAILED and a bounded ping received no replies. These observations do not
identify the underlying cause or prove the user selected the wrong machine.

The current IPv4 address was requested for reconciliation. No subnet scan or
automatic host-key acceptance was used. The implementation design is in
[Linux support/lifecycle](../superpowers/specs/2026-11-07-linux-support-lifecycle-design.md),
with an independent builder check finding no important unresolved design question.
User design approval and working test-host access remain pending.

## Resolved VM identity and fresh baseline

The user approved the design and provided the existing `osn-admin` login.
Read-only trusted Proxmox inventory identified `pve1` at10.83.1.11,
VM107 `test-agent-lin`, initially stopped. After checking exact name and SMBIOS
UUID`db12fb5c-3732-487f-911f-80e31f79b29b`, only107 was started.
Its QEMU guest agent reported MAC`BC:24:11:B6:B5:C1` and new DHCP191. The old162
alias was stale. Guest hostname is `alt-a2-pc86.sosnadmin.local`.

The SSH Ed25519 public key was read from `/etc/openssh` through the trusted
hypervisor and pinned in a separate task known-hosts file. Strict SSH to191 under
the supplied account succeeded. Passwords were entered interactively without
echo and were not stored. `osn-admin` is UID1000 and has no sudo permission;
no account, password or sudoers was changed. Root guest-agent administration
remains available for the dedicated test machine.

Actual OS is ALT Workstation K11.4/p11; Core and UserSensor156-alt5;
OpenSSH9.6p1-alt7; systemd258.9-alt1; Python3.12.13-alt1. CorePID1061 is active,
NRestarts0. There was no logged-in graphical user, only the display greeter.
Permanent DeviceUUID is29a8bed4-2894-40f7-89fb-07b3c7f633fe.
Private credential/identity/config/CA hashes and ownership were saved in ignored
task evidence; no plaintext credential was printed.

Root initially had242814976free bytes. An exact-directory guarded standard
APT archive cleanup completed0 after checking no package manager was active;
the four private/config hashes and CorePID were preserved. It freed about447MB,
leaving690069504bytes. Archives under/root and agent state were preserved.
Root is Btrfs; live tree du and df differ. No snapshots, historical packages or
test receipts were removed. Native build footprint/storage remains a gate.
