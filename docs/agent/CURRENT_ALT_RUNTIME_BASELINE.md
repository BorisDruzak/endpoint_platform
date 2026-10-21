# Current ALT runtime baseline

This is the accepted runtime behavior that the Endpoint Agent V2 split must
preserve.  The executable characterization lives in
`pc_agent/tests/runtime/test_current_gateway_characterization.py` and
`pc_agent/tests/runtime/test_current_update_characterization.py`.

## ALT 11 diagnostics candidate (2026-10-21)

The Linux adapters now use logind for local graphical session context,
metadata-only bounded journald profiles for `eventlog.query` and
`eventlog.recent_errors`, and local CUPS IPP over its Unix socket for printer
inventory/status and queue summary. Journal queries never request MESSAGE,
command lines or raw XML. Numeric `event_id=0` means no native Windows Event
ID; `message_code=journal_priority_N` preserves journal severity explicitly.
The service needs the supplementary `systemd-journal` group for system logs.
Diagnostic Context requests only selected journal metadata, never message text.

On an ALT Workstation K 11.4 / systemd 258 / KDE 6.7.4 reference workstation,
the candidate source observed a real X11/logind session, nonempty CUPS printer
inventory, an empty active queue, and bounded journal metadata. The empty queue
is not print-job or DLP acceptance. A 3569-package workstation reproduced a
false absence after the old 2048-package RPM cutoff; Linux enumeration now
admits at most 8192 records and rejects overflow rather than returning partial
success. Windows registry enumeration limits are unchanged.

The initial main 3.2.121 Core/launcher were built and installed as a native RPM
for lifecycle validation. New adapter code has not yet been released or accepted
as an installed candidate. User Sensor, Browser, DLP, Wayland, update/rollback,
reboot and full WSS command acceptance remain separate open gates in the
2026-10-21 parity plan. Historical checks below are not current release proof.

## KDE session sensor candidate (2026-10-21)

The candidate adds a credential-free per-user mode and an optional native
Qt6/KF6 helper, kept outside System Core. Linux IPC verifies kernel peer and
per-record credentials, graphical logind session and SSSD-backed UPN identity.
Only the platform adapter changes; local envelopes, Activity projection,
PolicyRuntime/cache, WSS ACK gates and Sensor Health remain shared.

The helper has been compiled and exercised in real X11 and Wayland sessions;
the Wayland check has a connected, enabled graphical output and includes a
domain-user session. Idle, lock availability and foreground PID were observed;
only a same-UID process name is projected. Placeholder-screen sessions do not
produce interactive observations. Wayland elapsed idle is unknown until a
resume establishes its clock, rather than treating unsupported polling as zero.
Shutdown removes only the helper's own ephemeral KWin script.

Linux Policy negotiation is reserved for Agent 3.2.122 or later. Browser and
DLP are still unavailable in this candidate stage and requested unavailable
sources fail with SENSOR_NOT_READY. The optional RPM integration, installed
User Sensor, offline/WSS acceptance and release gates
remain open in the parity plan. No new release or production rollout occurred.

## Gateway transport

- The only runtime controller origin is `https://endpoint.sosnadmin.local`.
- The Gateway creates its TLS context from the configured CA file and uses that
  context for the connector and Gateway request.
- A 401 or 403 device-credential rejection exits the Gateway loop; it is not
  retried or redirected to Helpdesk.
- Only transient connection failures and timeouts retry after the bounded poll
  delay.  TLS connector/certificate verification failures, HTTP response
  failures, credential/configuration failures, malformed controller payloads,
  and update-integrity failures are terminal for the process.
- Gateway command execution is restricted to `context.baseline.collect`,
  `context.health.collect`, `context.network.collect`, and
  `context.diagnostic.collect`.  Each command is parsed, acknowledged, run by
  the fixed context executor, and reported through the Endpoint origin; other
  contract capabilities receive a rejected result rather than dynamic execution.

## ALT update lifecycle

- The installed version is read from the strict immutable
  `/opt/endpoint-agent/current.json` selector schema:
  `schema_version`, `source_revision`, and `version`.
- Candidate artifacts must use the configured Endpoint HTTPS origin.  Redirects
  are disabled, so an artifact request cannot continue to another host.
  Streaming download verifies the expected SHA-256 and byte count before atomic
  publication.
- A verified eligible recommendation creates
  `updates/pending_alt_update.json` by atomic replace.  It targets
  `linux_amd64`/`canary`, records the Gateway request, and preserves the
  selected release as the rollback version.
- The unprivileged ALT launcher detects that durable pending path and delegates
  publication to the root-owned update worker.
- Before selecting a candidate, the root worker verifies the current immutable
  release and records its strict identity in root-owned `previous.json`.
- Selector replacement is the update commit point. Same-operation replay keeps
  a distinct verified previous selector and resumes history/request cleanup; a
  failed replacement restores the earlier `previous.json` record. Invalid
  replay authority is consumed into a fixed failure record, not left watched.
- Repeated candidate crashes create only the fixed service-writable rollback
  request. The root worker requires it to match `current.json` and
  `previous.json`, re-verifies the previous release, and atomically replaces
  the root-owned current selector. No request field chooses a path or command.
- A post-selector rollback replay recognizes the already-authorized previous
  selector and idempotently finishes terminal marker/request cleanup. Selector,
  complete release-tree, and pinned state-directory metadata are validated.
- After restart, the Gateway reports only a durable launcher outcome
  (`applied`, `failed`, or `rolled_back`) and retries the scheduled
  acknowledgement first.
  `startup_crash_rollback_requested` is not terminal; only the root worker's
  post-publication `startup_crash_rollback` marker becomes `rolled_back`.
