# Endpoint Capability Platform v2

Baseline: `main` at `31b3bdbbdcb07d2bb23beb9a6412e1ef2250fefd`, Agent
`3.2.65`, Alembic `0027_context_observed_backfill`. This design extends the
existing Module Recipe → Operation → Gateway WSS → Agent primitive → safe
Evidence flow. A Module remains a server-side declaration; an Agent release
delivers fixed runtime capabilities.

## Discovery and boundaries

The canonical committed registry is `endpoint_contracts/capabilities.py`.
The six existing IDs are `dns.resolve`, `network.ping`, `tcp.connect`,
`route.get`, `adapter.list`, and `system.service_status`. The registry already
binds authoring metadata, parameter DTOs and result DTOs. Gateway command
validation and result validation consume it. Gateway Hello intersects the
Agent's advertised set with server support, platform, version, flag and
policy. Module Lab/Run uses the connected session's effective set. Evidence
remains in the Operation retention flow (24-hour TTL with optional PIN).

Drift still exists in `ModuleCapabilityNameV1`, `ModuleStepSafeResultV1`,
`EndpointCapabilityAvailabilityV1`, the Agent dispatcher and Hello list, the
persisted step check constraint, Console names, and the six-item catalog
bound. The migration must expand the physical DB constraint *before* any new
step can be inserted. A regression test compares the registry with each
executable boundary and the migration constraint.

There is no capability-authoring endpoint. Descriptors may only select a
fixed typed handler; they contain no executable, command, script, path or
environment field. The pre-existing `system.service_status` contract and IDs
remain unchanged.

## Catalog

The following are proposed executable IDs. `W` and `ALT` mean an explicit
runtime implementation is required before the descriptor may advertise that
platform. Feature flags for all new groups start disabled. Every result has
bounded fields, a status/error code and a timestamp; every list has a fixed
item cap. Parameter/result schema versions start at `v1` per capability.

| Capability | Category | Windows | ALT | Risk | Policy | Inputs | Output |
| --- | --- | :---: | :---: | --- | --- | --- | --- |
| `system.resource_snapshot` | system | W | ALT | safe_read | none | none | uptime, CPU, memory, system volume free |
| `process.list` | process | W | ALT | controlled_read | process_metadata | none | ≤32 PID/name/state/CPU/RSS records |
| `process.find` | process | W | ALT | safe_read | process_metadata | bounded exact name | presence, count, ≤20 summaries |
| `service.list` | service | W | ALT | controlled_read | service_catalog | none | ≤8 fixed logical service facts |
| `service.status` | service | W | ALT | safe_read | service_catalog | enum `service_key` | one fixed service fact |
| `printer.list` | printer | W | ALT | controlled_read | local_printers | none | ≤16 installed printer facts |
| `printer.status` | printer | W | ALT | safe_read | local_printers | bounded installed printer name | existence and flags |
| `printer.queue.summary` | printer | W | — | controlled_read | local_printers | none | aggregate job counters and oldest age |
| `software.list` | software | W | ALT | controlled_read | machine_software | none | ≤32 machine-installed products |
| `software.find` | software | W | ALT | safe_read | machine_software | bounded exact/subname text | presence, ≤20 matches |
| `filesystem.free_space` | filesystem | W | ALT | safe_read | local_volumes | none | system volume key/type/bytes |
| `filesystem.path_exists` | filesystem | W | ALT | controlled_read | logical_paths | enum `path_key` | existence and kind |
| `filesystem.file_metadata` | filesystem | W | ALT | controlled_read | logical_paths | enum `path_key` | existence, size, modified time, optional version |
| `eventlog.query` | eventlog | W | — | controlled_read | event_profile | profile, lookback ≤60m, severity, count ≤32 | ≤32 metadata-only event summaries |
| `eventlog.recent_errors` | eventlog | W | — | controlled_read | event_profile | profile, lookback ≤60m | ≤20 metadata-only error summaries |

Catalog categories carry Russian labels from the backend: Сеть, Система,
Процессы, Службы, Печать, ПО, Журналы, Файловая система. Each descriptor
contains `display_name_ru`, category, platform list, minimum Agent version,
risk, consent, flag, policy, parameter/result schema versions, parameters,
execution timeout and result item cap. `safe_read` and `controlled_read` are
the only executable risk classes. Both have `consent_required=false` under
the existing administrative diagnostic policy. `controlled_write`,
`privileged_action`, and `continuous_sensor` are future architecture classes,
not public executable schema values in this release.

## Fixed platform policy

System and process facts use the locked `psutil` dependency (`7.2.2`).
`process_iter` requests only PID, name, status, CPU percent and memory info;
process name matching is case-insensitive plain text, never regex. Missing or
inaccessible process fields yield bounded unknown values, not command lines,
users, environment, paths or handles. The Agent limits iteration time and
returns explicit failure if it cannot finish within the command deadline.

`service.list` enumerates the *logical service catalog*, not the whole SCM or
systemd database. `service.status` selects an enum key. The catalog initially
contains the existing Endpoint Agent and updater keys plus a logical print
service (`Spooler` on Windows, `cups.service` on ALT). The ALT updater key maps
to the fixed `endpoint-agent-update.service` unit. Existing `system.service_status` keeps its
two-key behavior. No service action or executable path is exposed.

Printer reads enumerate installed local printers through the platform print
API or a fixed CUPS query. `printer.status` looks up a name in the bounded
enumeration before reading status. Queue summary aggregates counts across
local queues and discards job title, owner, document path, and spool content
before DTO construction. No printer on a machine is a successful empty result.

Windows software uses only machine-wide uninstall metadata from fixed
registry views. ALT uses a fixed RPM query, with no caller arguments. Names,
versions, publishers, architecture and source are bounded and deduplicated;
install paths and product/license keys never enter the result. Find uses plain
case-insensitive text on this inventory, without shell patterns.

Filesystem space uses fixed local volumes and excludes network shares.
Logical path keys are `endpoint_install_root`, `endpoint_data_root`, and
`endpoint_runtime_manifest`, mapped in Agent code to the existing Windows
Program Files/ProgramData and ALT `/opt/endpoint-agent`/`/var/lib/endpoint-agent`
locations. `file_metadata` permits only the runtime manifest key. Results do
not include the resolved path or file contents. A symlink/reparse boundary
must be checked before metadata access.

Event profiles are server/Agent-owned `system`, `application`, `print`, and
`endpoint`; there is no arbitrary channel, provider or full Security log.
Event queries are Windows-only in this release. The Agent reads fixed Windows
channels and returns event metadata with a generated event ID code; event
messages and XML/binary bodies are excluded. ALT journal queries require a
separate privacy and platform design, so ALT does not advertise these IDs.
The Agent enforces profile, time and count limits even if the server sent a
malformed command.

All new handlers have a bounded timeout, item count, text length and aggregate
payload target below the existing 64-KiB Gateway message ceiling. Gateway
validates the exact typed result before persisting an Operation step. The
server must never accept a result solely because its JSON is syntactically
valid. No new permanent result table or per-step audit event is created.

## Release and acceptance

Use Agent `3.2.67`: production already has a registered `3.2.66` build, so
that version cannot represent these new capabilities. Build the immutable runtime
manifest and Windows update ZIP. Keep all new server group flags false until
the matching runtime is installed and verified. The Console catalog is
metadata-driven; the Workbench builds step inputs from parameter descriptors.
Device detail displays the connected effective set, and old Agents show the
minimum-version incompatibility reason before Lab/Run.

Four server-side recipes exercise printing (status, queue, print service),
software find, system/space and process find. Pass validation, live Lab,
acceptance, publication, execution and Evidence without changing Agent source
between Module versions. Rollout order is LAB, local IT Windows, small IT
canary, then pilot, with WSS, Context, existing/new Modules, update and
rollback checked at each gate. ALT live acceptance is recorded separately
from automated ALT tests. DLP and continuous sensors use a future policy
controlled Agent sensor path and never enter this request-result catalog.
