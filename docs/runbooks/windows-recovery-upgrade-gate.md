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
