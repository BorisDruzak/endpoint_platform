# Independent pilot support access

Status: implemented in signed Windows Setup176 with separate Support1.0.1.
Three exact-media native/access canaries passed on2026-11-06, including stopped
Core/updater on101.120, explicit domain login and private offline dependencies.
Fleetpolicy10 and the six-device online cohort are accepted; actual176 download
and AUTO11 publication/cohort outcomes belong to
`docs/verification/2026-11-06-independent-support-access.md`. The original
101.146 incident below is historical and does not assert current device access.

## Approaches and selected direction

Direct administrator-network SSH would be simpler, but requires an inbound
workstation route/firewall policy and was unavailable on101.146 during this
incident. The user selected an outbound SSH tunnel through Endpoint: extra
gateway and service supervision are justified because access must survive a
Core/update-client fault without workstation command entry. Reusing Core's
command channel would retain the same failure dependency and cannot provide
the independent recovery channel requested here.

The design received a separate builder check; no material architecture
questions remained. Package/OS qualification, exact existing administrator
identity and approved public keys are implementation inputs, not claims that
those dependencies are already provisioned. At that original design checkpoint,
product implementation and live acceptance were outstanding; signed176
implementation and acceptance are recorded above.

## Required behavior

Install a separate versioned, signed Foundation component alongside the agent.
It starts independently of Core, UserSensor and EndpointSetupUpdater and keeps
its own protected keys, CA copy, policy credential, process supervision and logs.
It remains available when those components fail; its operation must not depend
on their health or native-update acceptance. Ordinary updates use Endpoint's
existing update controller; support access provides diagnostics and authorized
repair, preserving unknown native ownership and truthful receipts.

The workstation initiates the connection. Its SSH server listens only on
loopback; the gateway binds a distinct per-device loopback port. No workstation
inbound firewall/GPO exception or public gateway listener is introduced. An
operator connects through the authenticated gateway and verifies the workstation
host key bound to its Endpoint Device UUID, rather than trusting an IP/name.

Use distinct key roles: a unique locally generated tunnel key for each device,
a unique host key remaining on that device, and approved operator public keys.
No shared password or embedded private key. The gateway tunnel identity has no
shell/TTY/agent forwarding and may bind only its assigned loopback port. Windows
login uses explicitly configured existing administrative identities; installer
execution must not create an undocumented administrator account.

A central pilot policy controls enablement, expiry, operator keys and revocation.
Disabling/retiring a device revokes its tunnel and closes the owned connection.
The supervisor can receive its own bounded policy while Core is stopped, without
retaining a requirement for a healthy Core/WSS or continuing use of Core's token.
Keep connection/managed-operation audit. Do not promise complete arbitrary-shell
command recording from a TCP tunnel. Do not overwrite existing SSH configuration,
keys, service or rules. Complete product removal revokes and removes this owned
component; historical audit is retained.

## Existing bootstrap authority

`WindowsProvisioner._provision` exchanges the approved installation claim through
`HttpsWindowsEnrollmentClient.enroll`, persists CA/origin/device credential and
enrollment identity, and reads them back before its final `service.start()`.
This standalone path does not require successful Core execution or WSS. Register
only public support keys using that proved device identity over canonical HTTPS.
Retry key registration using the durable identity, never another claim/enrollment.
For already enrolled devices use the same authenticated registration operation.

The current wrapper attempts a service start earlier, so this does not claim
that no Core process ever ran. Support before enrollment or before any successful
native installation requires an explicit earlier authority contract; it cannot
be fabricated from hostname/IP or a reused consumed claim. The initial pilot
must report this boundary honestly.

## Dependency and acceptance gates

Use supported Microsoft OpenSSH components with recorded version/source and
signature verification. Check installed OS/dependency versions first. GitHub's
latest Win32-OpenSSH release is labelled Preview/non-production-ready; do not
silently choose it as a production dependency. OS capability installation may
need Windows Update/WSUS. Preserve unrelated existing SSH state and record
dependency/reboot/policy failures explicitly without forcing a reboot.

Qualify on a dedicated Windows canary: actual key-authenticated SSH command with
strict gateway/device host-key checks, then repeat with Core and observer stopped;
real reboot/reconnect, expiry/revocation, wrong key/port, credential rotation,
clone/key conflict, absent enrollment and installer rollback. A listener,
process, heartbeat or connected tunnel is not authenticated admin access proof.
Expose separate installed, policy-enabled, tunnel-connected and access-verified
states in Console; never label the first three as successful diagnosis access.

## Primary references checked

- [Microsoft OpenSSH configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
- [Microsoft key authentication](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)
- [OpenSSH forwarding restrictions](https://man.openbsd.org/sshd.8)
- [Win32-OpenSSH vendor releases](https://github.com/PowerShell/Win32-OpenSSH/releases)

Observed operator client: OpenSSH_for_Windows9.5p2; existing gateway: Ubuntu
OpenSSH9.6p1 Ubuntu-3ubuntu13.20. These observations do not select or qualify a
Windows support package for all workstations. The external workstation connector
catalog was read: it exposes ALT profiles, not a ready Windows repair operation.


## Implemented176 dependency and ownership details

The active signed Support service and its private state are siblings of Agent,
independent of Core/observer and outside MSI service/resource ownership. MSI
stages the signed helper and binds the identical uninstall Binary/Foundation
hash. Native rollback/unknown results preserve the active channel; normal known
uninstall has separate authenticated cleanup. Key/credential history is retained.

Existing valid Microsoft OS OpenSSH is read-only preferred. Fresh devices lacking
it use the original pinned Microsoft10.4.0.0p1-Preview ZIP inside signed Support.
Upstream is explicitly Preview/non-production-ready. Actual qualification here
is for the requested testing channel. A closed manifest, all15Microsoft PE
signatures, immutable public-code RX slot and private SYSTEM/Admin keys are
separate trust boundaries. No Windows capability installation, global SSH
service/configuration, PATH, registry-default-shell, firewall or GPO change is
used. Standard transient virtual-account authentication operations still occur.

The exact existing local/domain Windows principal must be verified; no guessed
account/password is created. Domain authorization requires fresh installed
running Support1.0.1, not installer intent. Default policy stays disabled, with
explicit approved operator keys and a maximum8hourlease. Actual SSH is separate
from registration, policy, version or tunnel state. See the runbook and exact
release record for expiry/revocation, native source qualifications and limits.
