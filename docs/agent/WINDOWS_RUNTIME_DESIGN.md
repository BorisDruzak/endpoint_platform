# Windows Endpoint Agent runtime contract

The Windows MSI registers `EndpointAgent` as an automatic-start service under
`NT AUTHORITY\LocalService`. SCM invokes the fixed Program Files service host:

```text
endpoint-agent-service.exe --agent-service
```

The host strictly reads `current.json` on every service start, rejects unknown
fields, non-triplet versions, traversal, and reparse points, and supervises
`versions/<version>/pc_agent.exe --windows-service-child`. Stop and shutdown
controls close the child's private stdin control pipe. This makes both a
candidate selector change and rollback effective at the next SCM start while
SCM itself remains bound to a stable installed path. The runtime continues to
own Gateway reconnects and update exit `42`; the host starts only the fixed
demand-start updater on that exit. The Windows boundary does not import Qt, UI
bridge, desktop APIs, Helpdesk, or the legacy `ws_agent` runtime.

## ACL contract

Both services enable unrestricted service SIDs. A deferred, non-impersonated
MSI action replaces the protected data-directory DACL, marks it protected from
inherited ACEs, and grants rights to exactly these principals:

- `SYSTEM`
- `Administrators`
- `NT SERVICE\EndpointAgent`
- `NT SERVICE\EndpointAgentUpdater`

The permanent `device-credential` grants read only to `EndpointAgent`; the
updater has write-only replacement access. `SYSTEM` and `Administrators` have
full control. Inherited ordinary-user entries are removed, so ordinary users
cannot read the device bearer. The data root grants EndpointAgent modify and
EndpointAgentUpdater write/delete inheritance; the updater service itself runs
as SYSTEM.

## Provisioning contract

`endpoint-agent-provision.exe` receives one-time enrollment material only from
standard input or `--material-file`. It has no claim/token command-line
property and never prints the material, device bearer, or enrollment response.
The non-secret Endpoint origin, CA filename, data directory, and installation
identifier may be supplied by MSI configuration.

The provisioner requires an absolute HTTPS Endpoint origin and an existing CA
file. It creates the protected data directory, atomically stages the
one-time material, calls the fixed Endpoint HTTPS enrollment route, and then
atomically persists both `device-credential` and the canonical
`enrollment-identity.json`. That identity is the server-issued `Device.id` and
is the sole identity accepted by the Gateway runtime.

After rereading and validating both permanent records, the provisioner starts
`EndpointAgent`. It removes the staged claim only after that proof and service
start complete; any earlier failure leaves the claim available for recovery.

`--print-safe-status` emits only service/account and boolean-like readiness
facts. It never emits the claim, bearer, raw enrollment response, or device
credential contents.

## Current delivery boundary

The Python contract is import-safe on non-Windows hosts and has injected SCM,
ACL, service-control, and enrollment adapters for tests. WiX binding, MSI table
inspection, real service registration, and a disposable Windows pilot still
require a build host with WiX 4; this work does not install, stop, or modify a
real service.
