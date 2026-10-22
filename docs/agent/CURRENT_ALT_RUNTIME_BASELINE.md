# Current ALT runtime baseline

This is the accepted runtime behavior that the Endpoint Agent V2 split must
preserve.  The executable characterization lives in
`pc_agent/tests/runtime/test_current_gateway_characterization.py` and
`pc_agent/tests/runtime/test_current_update_characterization.py`.

## ALT 11 private parity pilot (2026-10-21)

Agent 3.2.126-alt5 was compiled from
`fd9b918de6e976a085c96e38930515c61d2ee123` on ALT Workstation K 11.4,
Python 3.12.13, systemd 258.9 and KDE/KWin 6.7.4. This is a single-device
staging acceptance, without production rollout or stable-channel publication.
The current acceptance ledger is
`docs/superpowers/plans/2026-10-21-alt-linux-parity.md`; unresolved gates there
remain unresolved here. Historical checks below do not establish fleet readiness.

All 27 advertised Linux handlers ran against the real OS under the Core service
identity. Installed 3.2.126 completed baseline, health, network, session, inventory
and diagnostic Context over WSS, including a successful diagnostic operation.
Linux uses bounded logind/SSSD identity, metadata-only journald queries and local
CUPS IPP. No journal MESSAGE, window title, command line, document name or content
is collected. Diagnostic text obeys the Gateway's narrower 4096-character bound.
RPM inventory admits up to 8192 records and rejects overflow explicitly.

The optional user-sensor RPM supplies the credential-free per-user process,
Qt6/KF6 helper, KDE autostart, native messaging bridge and restricted root browser
policy helper. Core remains headless under endpoint-agent. Unix peer and message
credentials plus graphical logind sessions establish identity; ambiguous sessions
and unavailable identity fail closed. User processes never receive Core credentials.

Real domain-user Wayland and X11 sessions delivered ACTIVE/IDLE/LOCKED through the
shared Activity contract. Foreground carries only a same-UID process name and
category. On Wayland, idle remains UNKNOWN until an observed input resume establishes
its clock. KDE autostart atomically writes only the sensor's private environment
and restarts its unit, including quick X11/Wayland transitions. Placeholder displays
and unavailable idle/lock APIs do not manufacture ACTIVE observations.

The existing signed Browser Sensor 0.1.0 was installed by Chromium policy. Both
owned and external deployment modes produced ADMIN heartbeats and real upload/paste
SecurityEvents; installed 3.2.126 confirmed a fresh heartbeat and native-host READY.
Corporate policy files were preserved. Chrome was absent. The earlier Yandex
absence statement was incorrect: the 2026-10-22 follow-up found its 26.4.4.968
RPM installed before the original acceptance. Its verified ALT binary, managed
policy directory and shared Chromium native-host directory are now supported.
A fresh isolated Wayland profile installed the signed 0.1.0 extension as ADMIN
and returned an accepted native Hello, preserving the existing signature-extension
GPO. The corrected 3.2.127 frozen runtime acceptance is recorded in the ledger.
Physical USB plug/unplug
is explicitly postponed by the user. Kernel USB authentication/readiness and its
bounded persistence retry are verified separately from physical acceptance.

CUPS jobs reach the shared SecurityEvent spool. A real queued event survived a
service-scoped network fault and Core restart, then reached staging exactly once.
A CUPS startup outage produced SENSOR_NOT_READY/UNAVAILABLE; restoring the daemon
recovered Policy APPLIED and Print READY without a Core restart, and a new job was
received exactly once. USB/Print persistence retries retain the original event,
policy, timestamp and identifier. Browser Status still reports current policy errors;
Activity remains gated by successful application. Common Policy delivery retries
only transient SENSOR_NOT_READY after a 30-second backoff.

Real OTA delivered 3.2.124, 3.2.125 and 3.2.126 with server-confirmed applied.
A crashing fixture rolled back to 3.2.126; a following inner-digest-invalid fixture
was rejected and reported failed without a retry loop or a selector change.
Reporting uses the latest durable operation before its matching rollback marker.
The RPM external artifact sidecar lives outside the immutable release tree.
Registration and credential bytes survived OTA and RPM upgrades. No updater path,
manifest, permission, digest or TLS validation was weakened.
An actual machine reboot preserved selector and identity, restored headless WSS,
and completed six fresh Context collections plus a diagnostic operation. Normal
KDE logout exited the graphical session and user manager. The full Linux/PostgreSQL
gate passed 4372 tests (807 platform/resource skips); native privileged fixtures
and update characterization passed separately. Authenticated staging Console
acceptance confirmed device/Context/Activity/analytics/Policy/DLP views through
Playwright at desktop and mobile widths. The admin-only Policy projection exposes
whitelisted failures and individual source states with current-policy/freshness
checks. Controlled CUPS loss/recovery was visible in that UI. The follow-up
reproduced scheduler saturation during cups-browsed network queue discovery:
the default 100 simultaneous clients caused local metadata queries to time out
before response headers, with matching Max clients reached log entries. The
reference host's temporary MaxClients 256 setting allowed 180 successful requests
but only postponed exhaustion. Native socket tracing identified two cleanup
defects in cups-browsed 2.1.1: update_cups_queues early exits (upstream fix #67)
and every successful is_disabled response. The latter leaked one connection per
call; an extracted native regression reproduced ten leaked descriptors in ten
calls for idle, stopped and missing queues, versus zero after the one-line fix.
The local 2.1.1-alt1.endpoint2 RPM contains those four cleanup calls, with the
vendor build settings retained. Original scheduler and discovery configuration
are retained; this is a reference-host OS package correction, separate from
Agent 3.2.127. Agent timeouts, TLS, print ACLs and AD settings were unchanged.
The previously enabled cups-browsed service was also restored after the earlier
outage test had left it stopped. With the corrected OS package and original
100-client scheduler, 300 real printer/audit queries passed over five minutes
(maximum 10.01ms); descriptors fell from 11 to 9 and stayed at 9 for the last
minute. A held synthetic job reached staging exactly once with Print READY and
the same Core PID. Only the own job/queue and private fixtures were removed.
The Agent separately handles the normal no-printers IPP response.

## Gateway transport

- The default runtime controller origin is `https://endpoint.sosnadmin.local`.
  The exact canonical staging origin additionally requires the fixed approved
  staging markers; arbitrary controller origins remain rejected.
- The Gateway creates its TLS context from the configured CA file and uses that
  context for the connector and Gateway request.
- A 401 or 403 device-credential rejection exits the Gateway loop; it is not
  retried or redirected to Helpdesk.
- Only transient connection failures and timeouts retry after the bounded poll
  delay.  TLS connector/certificate verification failures, HTTP response
  failures, credential/configuration failures, malformed controller payloads,
  and update-integrity failures are terminal for the process.
- Gateway command execution uses the fixed executor: six Context profiles and
  platform-supported registry primitives. Linux currently implements 27 handlers
  in total. Server feature flags and the fixed network-target policy still gate
  public availability; advertising a handler alone does not authorize its use.
  The private staging Console was verified with 17 read-only primitives enabled;
  optional network probes remain disabled there.


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
