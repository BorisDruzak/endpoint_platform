# Windows recovery upgrade gate

`GATEWAY_MINIMUM_AGENT_VERSIONS` is an optional JSON object mapping canonical
device UUIDs to numeric three-part minimum Agent versions. An empty value leaves
the existing fleet behavior unchanged. The setting accepts at most 128 explicit
devices and rejects malformed input at server startup.

For an authorized canary, configure only its UUID. The Gateway validates device
authentication and hello identity before checking the floor, and rejects an older
Agent before opening its presence session. Device-authenticated HTTPS update
routes remain available. Legacy Agents receive WSS close 1002; Agents advertising
`endpoint.recovery-update.v2` also receive `agent_upgrade_required`. Neither
response enables HTTP command fallback or establishes ONLINE presence.

Agent 3.2.80 keeps its service-owned HTTPS recovery supervisor running after this
control rejection. Update application still requires the fixed SCM updater and a
fresh authenticated WSS handshake from the candidate. Local corrupt update state
disables update progress while healthy WSS can continue. Credential rejection and
TLS trust failure remain terminal.

Before live acceptance, retain the previous configuration and release revision.
Remove the canary floor after acceptance and restart the verified server service
using the deployment procedure. Verify both the canary and an untargeted device.
Do not configure a global floor or reinterpret HTTPS availability as presence.

The immutable 3.2.79 parser compares response channel to its query channel.
Although the server now returns the assigned release channel independently of
that query, this does not repair already installed 3.2.79 bytes. Record an actual
stable-response rejection as a failed legacy upgrade scenario; changing the
release to canary is not evidence for stable-channel compatibility.

## Corrective 3.2.81 bridge and offline worker

For an explicitly authorized migration, publish a new immutable canary build
3.2.81 and assign only the selected legacy device. Its unchanged 3.2.79 parser
accepts the channel `canary` response. This is a compatibility bridge, not a passing
retroactive stable 3.2.80 acceptance. Never replace 3.2.80 bytes or retag a
registered 3.2.81 identity. A later stable rollout uses its own release identity.

ZIP updates change the selected Agent runtime, not fixed MSI-owned service
binaries. Identify the legacy worker used during 79→81 independently from the
corrected worker. Install canonical MSI 3.2.81 to transition EndpointAgentUpdater
to `endpoint-agent-updater.exe --updater-service`. It retains LocalSystem,
demand start and service SID/DACL restrictions. EndpointAgent keeps its original
fixed launcher and LocalService identity.

The MSI builder rejects network modules/native TLS/socket libraries before
binding, including reused builds. `--verify-offline` checks imports and MSI-owned runtime validation in a temporary fixture;
it must never be presented as evidence of SCM application. Verify the actual
registered updater executable, archive proof, real SCM execution, WFP events,
WSS-bound startup confirmation, terminal reports and rollback separately.

### Historical 3.2.81 ZIP to MSI ownership handoff

Installing MSI 3.2.81 over its identical ZIP runtime leaves the old ZIP receipt
and bundle manifest beside the new MSI ownership marker. Canonical preflight
rejects this mixed provenance. This handoff is an explicit operator step;
the MSI and canary wrapper do not automatically retire those ZIP records.

Before retiring them, verify the active MSI product and release sidecar, the
MSI marker component GUID, selector version/source, exact ZIP receipt identity,
every payload file size/hash and the complete file inventory. They must all
identify the same retained canonical runtime. Stop EndpointAgent, archive only
`.endpoint-update.json` and `endpoint-update-manifest.json` in a protected
SYSTEM/Administrators backup, then restart it and rerun canonical preflight.
Preserve the MSI marker, payload bytes, credential and selector. If any identity
or file differs, stop the handoff; do not remove evidence to obtain a passing
preflight. Clean MSI installation has no preceding ZIP receipt to retire.

## Canonical 3.2.82 Setup gate

The historical 81 handoff above is not an 82 installation or repair procedure.
For 82 use only the approved single-file signed/timestamped Setup EXE. Its
authenticated installer transaction owns automatic exact ZIP-to-MSI handoff,
retained core preservation, native feature repair and interrupted recovery.
Do not install ZIPs manually, edit receipts, clear journals/fences, or enable
quarantined services to obtain a passing result. Preserve immutable 79/81 bytes,
enrolled identity, credential, CA and origin.

Run the SAME elevated Setup EXE with `--preflight` immediately before the
authorized install/upgrade. It prints one bounded JSON record and does not
enroll, stop/configure services, download, publish/clean state or run the
installer transaction. Canonical restricted package costing reads the verified
embedded package and sums native, wrapper, preparation and retention allocations
with a per-volume margin. Target-version-only collection reports unknown costs;
unavailable complete canonical costs are DISK_UNKNOWN, never readiness.
PyInstaller and the restricted MSI engine can perform temporary scratch IO;
verify unchanged protected state and native registration at the signed artifact
acceptance gate rather than claiming zero host IO.

To save fleet facts as an explicitly requested evidence artifact, invoke the
canonical collector with its existing expected host/install/data arguments plus
`-SetupPath <exact-approved-Setup-EXE> -TargetVersion 3.2.82 -FleetEligibilityOnly`
and a NEW `-OutputPath` outside protected machine roots. The collector rejects
invalid/untimestamped signatures, reparse paths, nonzero exit, oversized or
unexpected JSON, mismatched target and unsupported facts. Omit
`-FleetEligibilityOnly` for the existing installed-agent acceptance projection;
it still requires its separate installed checks and optional command completion.

Treat UPDATE_IN_PROGRESS (including malformed recovery evidence and surviving
installer transactions), PROVENANCE_CONFLICT, FOUNDATION_UNKNOWN,
DISK_INSUFFICIENT/DISK_UNKNOWN, SERVICE_INVALID, CREDENTIAL_REPAIR_REQUIRED and
TLS_REPAIR_REQUIRED as non-ready. Disabled services under a surviving fence are
intentional installer/reboot degradation, not an unfenced service repair. A
current core plus stale foundation or required equal-version handoff cannot be
ALREADY_CURRENT. A complete compatible newer ZIP/live MSI/retained core retains
its independent provenance and must not be relabeled as the target MSI's core.

Credential shape cannot prove authentication, installed CA cannot prove live
hostname/chain validation and a protected old canary status cannot prove current
WSS presence. Fleet facts therefore expose those live claims as unknown.
Installed verifier READY accepts the collected local evidence, including its
historical transport record; it is not fresh connectivity or fleet approval.
Post-freeze acceptance must correlate fresh authenticated provider session /
last_seen, actual strict TLS/WSS, a matching completion operation and installed
READY with unchanged identity and native state. No global fleet floor or mass
rollout follows from this report. Setup rechecks active state under the common
mutation exclusion boundary; a read-only eligibility snapshot is not a lock.
