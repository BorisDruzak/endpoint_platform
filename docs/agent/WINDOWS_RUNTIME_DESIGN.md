# Windows Endpoint Agent runtime contract

The Windows MSI registers `EndpointAgent` as an automatic-start service under
`NT AUTHORITY\LocalService`. SCM invokes the fixed Program Files service host:

```text
endpoint-agent-service.exe --agent-service
```

The host strictly reads `current.json` on every service start, rejects unknown
fields, non-triplet versions, traversal, and reparse points, and supervises
`versions/<version>/pc_agent.exe --windows-service-child`. A newly built MSI
installs selector schema version 1 (`schema_version`, `source_revision`, and
`version`), where `source_revision` is the exact 40-character Git revision
used for the MSI build. A legacy version-only selector remains launch-compatible
only to make an in-place upgrade safe; it is not provenance-complete and cannot
pass the Windows diagnostic-canary preflight. Stop and shutdown
controls close the child's private stdin control pipe. The child watches that
pipe with a dedicated daemon reader rather than asyncio's default executor, so
a runtime exit `42` cannot hang `asyncio.run()` while the host pipe remains
open. This makes both a
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
as SYSTEM. Before replacing the DACL, the action validates the entire existing
path chain against symlinks/reparse points and requires trusted SYSTEM or
Administrators ownership for the ProgramData subtree.

## MSI initial-runtime transition

Routine packages pin the complete staged runtime tree and producer toolchain in
`initial-runtime.json`; the declared version must match `AGENT_VERSION`. An
approved source transition requires both release switches, a new version, and
a new component GUID. The MSI stores its validated old/new versions in a fixed
HKLM contract and runs the no-path selector migration action after service
installation/ACL setup but before `StartServices`. If `current.json` still
names the old initial runtime, it is atomically moved to the installed new
runtime. A different selector is preserved only when its executable is a
regular non-reparse file inside `versions/`; otherwise installation fails
before service start.

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

## Update handoff and confirmation

While a WSS session is healthy, `EndpointAgent` asks only the same Endpoint
HTTPS origin for a `windows_amd64` canary recommendation. It downloads a ZIP
only through the configured CA-verified session, verifies the published hash
and size, then applies the fixed protected DACL to the downloads directory,
artifact, and `pending_update.json`. The agent exits with code `42`; it never
selects an updater executable or passes a network URL to the updater.

`EndpointAgentUpdater` remains demand-start `LocalSystem` with no HTTP client
or listening socket. It accepts only that fixed protected pending path, stops
the fixed agent service, verifies the candidate, atomically publishes the
immutable version and selector, and restores the preceding selector on failure.
After the selected candidate has completed its Gateway WSS handshake, the
agent writes the operation-bound local startup proof and reports `applied` to
the Endpoint update API. A local proof without a matching selected version is
not reportable; a `scheduled` acknowledgement alone is not success.

## Current delivery boundary

The Python contract is import-safe on non-Windows hosts and has injected SCM,
ACL, service-control, and enrollment adapters for tests. The Windows build
host produces and inspects the WiX MSI, and the disposable local Windows pilot
is used for installation, protected enrollment, WSS and update acceptance.
