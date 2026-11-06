# Independent Windows support access

This is a separate support channel for diagnosing an enrolled Windows device
when Core, EndpointAgentUpdater or EndpointSetupUpdater is unavailable. Ordinary
software updates still use the signed full Setup workflow. Installing a component,
enabling policy, establishing a tunnel and verifying administrator access are
different states; a connected tunnel alone is not successful administrator access.

## Components and trust boundary

`EndpointSupportAccess` is a signed LocalSystem service with no dependency on
Core, the update worker or its scheduled observer. Its onefile executable lives
in `C:\Program Files\Endpoint Platform\Support\EndpointSupportAccess.exe`.
Its keys, separate CA, policy credential and configuration live in
`C:\ProgramData\Endpoint Platform\Support`. Both are siblings of Agent, with
protected SYSTEM/Administrators access. Agent identity and credentials are read
only during installer bootstrap after durable enrollment proof; service startup
does not read them.

The service runs a distinct Microsoft OpenSSH daemon at `127.0.0.1:22222` and
makes an outbound authenticated connection to `endpoint.sosnadmin.local:2222`.
The gateway's dedicated SSH daemon binds its LAN address only. It has a complete
separate configuration; the existing administrator SSH service, configuration,
keys and firewall are not changed. A root-owned broker permits each unique
`eps-<device UUID hex prefix>` account to bind only its assigned gateway loopback
port in32000..41999. No shell, TTY, agent forwarding or direct TCP forwarding is
permitted for tunnel identities. Workstation host keys are bound to Device UUID,
not inferred from hostname, IP or an unauthenticated scan.

Host keys, device tunnel keys and approved operator keys have distinct roles.
The installer generates device private keys locally; private keys and enrollment
material are never embedded in a release. The Windows login must already exist
and be an enabled administrator. The pilot uses `test_agent_win` on101.120;
the user selected existing `admin-2` for subsequent Windows devices. No Windows
administrator account is created by this feature.

## Policy and revocation

New registrations are disabled. An administrator with existing `updates:write`
scope and valid CSRF sets the exact device, existing Windows login, approved
operator public keys and an aware future expiry of at most8hours. This is a
testing access lease; installation does not grant permanent support access.

The component polls HTTPS with its independent `eps1` credential and the copied
CA. It requires a fresh policy after every service start. A monotonic60-second
freshness deadline bounds access during DNS/TLS/API failure; disable/revoke stops
owned SSH descendants. The unprivileged server exporter emits60-second snapshots;
the separately installed root broker reconciles them every5seconds. Missing,
invalid or stale snapshots remove authorization and terminate owned sessions.
Gateway startup clears retained keys before accepting connections. Device
retirement or source-credential revocation also removes support authority.

Disabling a policy preserves the independent credential and permits later
explicit enablement. Revocation invalidates its generation. Recovery/rebinding
requires explicit administrator authorization followed by durable authenticated
installer registration. An install retry never consumes another enrollment claim.
Historical audit is retained. The access-verification record is clearly labelled
an operator attestation: a TCP tunnel cannot promise recording of every arbitrary
shell command.

## Installation and operating-system dependencies

Full Setup stages the signed independent executable. `--install` provisions from
the durable enrolled identity, creates private support state and registers the
independent service. An absent OS dependency is installed using the Microsoft
OpenSSH capability; Microsoft signature, version and hashes are recorded. A
required reboot or policy failure is reported rather than forced. Existing SSH
state is preserved. The support listener itself needs no workstation inbound
firewall exception or GPO change.

The service pins the recorded OS executable hashes. If Windows replaces OpenSSH,
support fails closed until the signed installer revalidates dependencies; this
is a support-component condition and must not be presented as an agent update
success or silently repaired by arbitrary remote code. Component errors are
reported separately from authoritative native agent installation receipts.

`--uninstall` unregisters independent authority, stops/removes only its owned
service and removes only its owned data. Product uninstall must execute cleanup
at native commit, so a rolled-back MSI removal cannot erase support private keys.
Ordinary upgrades retain identity and keys. No historical native UNKNOWN outcome,
journal or recovery ownership is cleared to install this feature.

The standalone pilot alongside historical172 is not owned by that historical
MSI. If removing that pilot before upgrading to a support-aware full Setup,
explicitly invoke the signed component's `--uninstall`. Read-only historical
uninstall finalization and staged runtime retirement do not gain new mutations.

## APIs and deployment assets

- `endpoint_contracts/support_access.py`: strict bounded wire models.
- `/agent/v1/support-access/register`: durable device-authenticated public-key
  registration; independent bearer for `/policy`, `/status` and `/unregister`.
- `/api/admin/support-access/devices/{device_id}`: policy and separate component,
  tunnel, freshness and operator access-proof states; audited policy operations.
- `endpoint_server/support_access/`: database authority and unprivileged exporter.
- `deploy/server/support_access_broker.py`: standalone stdlib-only privileged
  broker installed root-owned at `/usr/local/libexec/endpoint-support-broker.py`.
- `endpoint-support-{gateway,exporter,broker}.service` and broker timer:
  independently supervised transport, snapshot publication and revocation.
- `pc_agent/platform/windows/support_access*.py`: isolated policy, native process
  and SCM boundaries; `pyinstaller_windows_support_access.spec`: signed artifact.

The gateway LAN listener and the `SUPPORT_GATEWAY_HOST`, `SUPPORT_GATEWAY_PORT`
and `SUPPORT_GATEWAY_HOST_PUBLIC_KEY` settings are explicit deployment changes.
Migration0046 is additive and seeds no policy or workstation access.

## Acceptance and release gate

First qualify only192.168.101.120. Save the prior agent/updater/task state and
private identity proof; preserve the existing direct SSH service. Verify an
actual key-authenticated Windows command through the gateway with strict gateway
and UUID-bound device host-key checks. Repeat with Core, updater and scheduled
observer stopped, across natural reboot/reconnect, and after service restart.
Verify wrong operator/gateway/device keys, wrong gateway port, lease expiry,
disable/revocation and stale-policy cutoff. Verify reinstall/rollback and explicit
key recovery. Restore original agent/updater/task state after fault injection.

Only after these checks pass may a new immutable full Setup be signed, tested
from the actual source Foundation and qualified in Console. The user authorized
subsequent fleet delivery through Endpoint. Keep normal qualification gates and
bounded waves; unsupported/offline devices are reported separately from successful
installations. Preserve historical172 bytes and every earlier failure receipt.

Actual command outputs, artifact digests and live device results belong in a
dated verification receipt. This runbook describes the required workflow and
does not itself assert that any live check or rollout passed.
