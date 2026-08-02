# Windows Endpoint Agent runtime contract

The Windows MSI registers `EndpointAgent` as an automatic-start service under
`NT AUTHORITY\LocalService`. The service executable uses only the neutral
headless entrypoint:

```text
endpoint-agent.exe --windows-service
endpoint-agent.exe --verify
endpoint-agent.exe --print-safe-status
```

`--windows-service` dispatches through pywin32 only at execution time. Its
SCM coordinator reports start/running/stopping/stopped states and translates
stop and shutdown controls into cancellation of the existing neutral runtime.
The runtime continues to own Gateway reconnects and update exit `42`. The
Windows boundary does not import Qt, UI bridge, desktop APIs, Helpdesk, or the
legacy `ws_agent` runtime.

## ACL contract

The protected data directory and its enrollment state use explicit Windows
DACLs for exactly these principals:

- `SYSTEM`
- `Administrators`
- `NT SERVICE\EndpointAgent`
- `NT SERVICE\EndpointAgentUpdater`

The permanent `device-credential` grants read only to `EndpointAgent`; the
updater has write-only replacement access. `SYSTEM` and `Administrators` have
full control. Inherited ordinary-user entries are removed, so ordinary users
cannot read the device bearer. The data directory grants the two service
accounts modify access for service state and atomic replacement.

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
ACL, service-control, and enrollment adapters for tests. The MSI tables,
pyinstaller provisioner artifact, real service registration, and a disposable
Windows pilot are follow-up packaging and validation work; this contract does
not install, stop, or modify a real service.
