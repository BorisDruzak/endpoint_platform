# Endpoint Policy & DLP Foundation v1 Implementation Plan

> **For agentic workers:** Execute the remaining unchecked tasks in order; each task ends with focused tests and a review of the complete diff. The supplied specification is the authority for scope and acceptance.

**Goal:** Deliver server-owned continuous Policy, Activity, browser and audit DLP sensors, safe event storage, and Russian Console status on a managed Windows canary.

**Architecture:** Keep Policy and sensors outside Module Platform. The authenticated Gateway WSS carries separately typed policy, activity and security-event messages only for Agents that advertise support. The LocalService Agent validates data from a per-user sensor and Chromium native messaging bridge through a local named pipe. In `agent_managed` mode, a separate fixed SYSTEM component applies only the approved extension's machine-level browser policy; transition to `external_managed` may remove only its own exact, unchanged entry, then makes no installation-policy write. Server storage keeps immutable policy versions, a current activity projection, and expiring typed security events.

**Tech stack:** Python 3.12, Pydantic 2.12+, FastAPI, SQLAlchemy/Alembic, PostgreSQL, Windows APIs/pywin32, Chromium MV3 JavaScript, React 19, WiX MSI, PyInstaller.

**Spec:** `docs/superpowers/specs/2026-09-25-endpoint-policy-dlp-foundation-v1.md`.

## Baseline and discovery

- `origin/main` and the indexed GitNexus `endpoint_platform` revision were both `8044ff1ee993754a295f10f47672ce9402e6f10b` on 2026-09-25. This isolated branch starts there. The prior checked-out capability branch was ancestor `959ba1c`; its tree is clean and remains separate.
- `pc_agent/version.py` reports Agent `3.2.67`; Alembic head is `0028_capability_platform_v2`. Confirm server release registry before choosing the next Agent version.
- `endpoint_contracts/gateway_ws.py` defines discriminated, strict WSS envelopes; `endpoint_server/gateway/ws_routes.py` authenticates `/agent/v1/connect` and dispatches hello/heartbeat/command frames. Existing `policy_update_v1` changes *effective capabilities* and must remain distinct from Endpoint Policy.
- `endpoint_server/context` has `ContextCurrent`, semantic hashing, 24-hour hot retention and `DeviceEvent`; `endpoint_server/operations/evidence.py` owns 24-hour operation evidence. New activity observations need a dedicated typed path but can reuse Context current/snapshot retention semantics. Security events need their own table and cleanup.
- `packaging/windows/wix/Services.wxs` installs a LocalService Agent and a user Tray through HKLM Run. Reuse this login startup for a separate unprivileged user sensor. `pc_agent/platform/windows/tray_status.py` is a one-way public file, unsuitable for browser-to-Agent messages.
- Windows MSI stages an immutable runtime plus fixed launcher/tray binaries; `packaging/windows/build-update-zip.ps1`, updater selector, startup proof and canary verifier form the release gate. Browser artifacts can reuse `Settings.artifact_root` and verified SHA/download code, but managed browser updates require a new narrowly public, immutable HTTPS route (existing Setup route is admin-only).
- `webapp/src/App.tsx` owns Russian navigation; `FleetPages.tsx` owns device details. Console APIs live under `endpoint_server/console` and use admin session/CSRF and bounded DTOs.

## Phase 0 decisions

1. **WSS path:** Advertise `endpoint.policy.v1`, `endpoint.activity.v1`, `endpoint.browser-status.v1`, and `endpoint.security-events.v1` as protocol features in Agent hello, not Module capabilities. Send a `endpoint_policy_delivery_v1` envelope after gateway hello and on assignment changes; accept typed policy acknowledgement. Independently accept activity observations, coalesced per-browser status and bounded event batches, and ACK only committed batches. Keep sequence and 64-KiB gateway limit. Add browser-status negotiation and transport with the Task 8 projection; the completed Task 2 policy path need not be rewritten.
2. **Old Agents:** Check advertised protocol features and minimum Agent version before delivery. An old hello receives its existing gateway hello and command flow unchanged; server derives `UNSUPPORTED` and an update prompt.
3. **User startup:** Install `EndpointUserSensor.exe` next to `EndpointAgentTray.exe` with an HKLM Run value and per-session mutex. MSI upgrade stops/restarts it under the same ownership rules as Tray. The user process receives no device credential.
4. **Local IPC:** Service-owned Windows named pipe, with a DACL granting the service SID, SYSTEM and the expected interactive user SID. On every connection impersonate the pipe client, validate token SID and `ProcessIdToSessionId` against the current interactive session, enforce 16-KiB framed typed messages, then revert impersonation. Never open localhost TCP. Explicitly test rejection before allowing browser-origin data into Agent state.
5. **One CRX:** Chrome Enterprise and Yandex Browser for Organizations document managed force-install from an update URL. A single signed CRX is the target; same-package acceptance is unproven. Google requires an Active Directory domain-joined computer for automatic installation of a non-Web-Store Chrome extension. Yandex consumer-browser security documentation describes a restriction on `ExtensionInstallForcelist`; the installed browser management mode and effective policy status must decide whether `agent_managed` is supported. On 2026-09-25 the reference workstation has Chrome `153.0.8010.53` and Yandex Browser `26.8.3.1002` installed, so both must pass the managed-policy installation and native-messaging handshake with the identical CRX. Recheck both installed versions and effective enterprise-policy support at the live gate. In `agent_managed`, begin with the extension absent and prove Agent-driven force-install; in `external_managed`, Agent only reports observed state.
   Yandex documents that its Windows extension policies work only when set inside a domain or through its management console. The reference workstation was domain-joined to `sosnadmin.local` when checked on 2026-09-25, but membership does not prove that an Agent-written local machine value is accepted. Reconfirm the management context and prove the exact Agent-owned value is effective in `browser://policy` before claiming `agent_managed` support. If the local value is ignored, report the unsupported browser/context and resolve an official enterprise-policy path before completion; keep compliance non-compliant without using profile installation.
6. **Stable ID:** Generate/store a dedicated signing private key outside Git in protected operator storage, derive and pin the Chromium extension ID from its public key, and fail release build if ID changes. The native host manifest lists exactly that `chrome-extension://<id>/` origin.
7. **Artifacts:** Use the existing `artifact_root`, digest verification and immutable metadata pattern, with public fixed routes for the signed CRX and update XML over `endpoint.sosnadmin.local`. No path-derived directory access or directory listing. The approved extension ID and update URL are typed server-owned policy inputs to the applicator, never free registry strings from an endpoint user.
8. **Activity APIs:** In the user session, use `GetLastInputInfo` plus `GetTickCount64`, `WTSRegisterSessionNotification`/`WM_WTSSESSION_CHANGE`, `GetForegroundWindow` + `GetWindowThreadProcessId`, and process basename only. `GetLastInputInfo` is session-specific, which is why the service cannot poll it in session 0. Never read titles or command lines.
9. **USB/print APIs:** Use a service-side `CM_Register_Notification` (or existing service event callback where proven) for USB arrivals/removals and bounded device properties; use `FindFirstPrinterChangeNotification`/`FindNextPrinterChangeNotification` for print jobs, discarding document title and spool content before serialization.
10. **Reliable scope:** USB lifecycle, spooler print notifications, browser file-input selection and paste occurrence are feasible without a kernel driver, subject to lab proof. Removable writes and network shares are deferred unless a tested, privacy-safe OS mechanism is found; no driver, blocking or content capture is in v1.

Relevant official documentation: [Chrome ExtensionSettings](https://support.google.com/chrome/a/answer/9867568?hl=en), [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [Yandex force-install](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist), [Yandex native messaging allowlist](https://browser.yandex.ru/support/browser-corporate/ru/policy/native-messaging-allowlist), [GetLastInputInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo), [WTS session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification), [device notifications](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerdevicenotificationa), [print notifications](https://learn.microsoft.com/en-us/windows/win32/printdocs/findnextprinterchangenotification).

Chrome's `ExtensionSettings.update_url` selects the initial installation source; later updates can follow the extension manifest URL unless `override_update_url` is enabled. Keep the signed extension manifest and managed policy on the approved Endpoint HTTPS source, and verify an actual subsequent update. Yandex `ExtensionSettings` can override other extension policies, so reject an unsafe merge or precedence conflict rather than assuming the Agent's value wins.

### Browser deployment ownership and privilege boundary

The supplied addendum changes only Browser Sensor deployment ownership. `browser_sensor.deployment_mode` is a strict `agent_managed | external_managed` enum. The current MSI installs `EndpointAgent` as **LocalService**, so its runtime cannot write HKLM browser policy. Keep that account and add a narrowly privileged, signed, fixed-function helper/service controlled over an authenticated local channel by the Agent service SID. Authenticate that SID for every request; use a versioned typed apply/relinquish operation, not a general registry-write interface. It may write only the pinned Endpoint extension ID and approved HTTPS update URL in Chrome/Yandex machine policy, and its own ownership marker; it must reject arbitrary registry paths, browser IDs and URL values. No entire-Agent elevation.

The installed 3.2.71 pilot exposed an additional Windows access boundary: the pipe's Agent ACE needed `FILE_READ_ATTRIBUTES` for `CreateFile`, while the helper process and token separately needed Agent-SID `PROCESS_QUERY_LIMITED_INFORMATION` and `TOKEN_QUERY` for server authentication. Commit `fd81d6b2f3e135a8ab9add1a325d6b9dddb41a4f` adds these narrow grants before the helper listens. The 3.2.72 canary must prove a fresh helper process works without temporary diagnostic ACL changes.

Chrome `ExtensionSettings` is preferred; Yandex `ExtensionInstallForcelist` or `ExtensionSettings` is selected after verifying actual installed version and effective policy. Before any registry write, read existing policy and ownership marker, parse/validate the complete value, preserve unrelated entries, and compare the pre-write value immediately before replacement. If the value is GPO/cloud-owned, malformed, concurrently changed or incompatible, fail closed as `POLICY_CONFLICT`. Reapplication of identical state is a no-op. On transition to `external_managed`, the applicator may remove only its own exact, unchanged extension entry and marker under prior Agent ownership; it preserves every foreign entry. If cleanup is unsafe, report conflict and do not claim hand-off completed. After safe hand-off, `external_managed` makes no installation-policy write. Native-host registration remains MSI-owned; do not set `NativeMessagingBlocklist = *` because other corporate hosts may be in use.

For status and acceptance, keep three observations separate: the Agent-owned machine policy value, browser-side evidence of managed installation, and the extension's Bridge heartbeat. A registry write does not prove that either browser accepted the policy. `BrowserFamilyStatusV1.installation_policy_state = APPLIED` describes the machine value; the server now exposes a separate derived `effective_policy_state` that requires current policy ACK, a matching machine value, a running detected browser and a fresh extension heartbeat reporting administrative installation. This derived state does not read the exact effective enterprise-policy value. If that evidence is absent, report browser effectiveness as unknown. Task 9 may show `Политика установки: применена` only with the derived browser-side evidence. Task 11 must still inspect each installed browser's effective policy page and collect download, Bridge handshake and heartbeat evidence independently before claiming force-install acceptance.

## Global constraints

- Disabled feature flags by default; no rollout without a scoped test policy.
- No key, clipboard, browser DOM/page, document/file content, filenames, titles, query strings, command lines or direct browser authentication to Endpoint.
- Only `disabled` and `audit` DLP modes; no blocking, quarantine, service restart, process kill or arbitrary script/path input.
- Strict bounded DTOs, no arbitrary JSON passthrough, event batch at most 50 and 64 KiB, browser message at most 16 KiB.
- Policy versions immutable; server derives compliance; Agent caches last applied policy and retries events until persisted ACK.
- Preserve Agent identity and Tray through update/rollback; do not put continuous sensors into Module capability catalog.
- Do not edit browser profiles or install CRX directly; `agent_managed` uses only machine-level enterprise policy, and `external_managed` leaves it to GPO/Ansible. Never set a global native-messaging blocklist automatically.
- No Helpdesk integration, bulk GPO/Ansible rollout or service API v2 in this plan.

## Review focus

1. An old Agent or rolled-back Agent must remain connected and receive no incompatible frame; add WSS coexistence tests in Tasks 2 and 10.
2. A user switch or concurrent RDP session must not let one user's browser report through another session's pipe; add impersonation/session tests in Task 5.
3. URLs with credentials, Unicode hostnames, ports, query and fragments must normalize safely or reject; add browser normalization and server DTO tests in Tasks 3 and 4.
4. Replayed event ACK, crash between DB commit and ACK, and spool overflow must never duplicate rows or grow disk unbounded; add fault tests in Task 7.
5. Browser closed, browser absent, extension never seen and extension stale must be distinct per browser, with no false installation failure on heartbeat absence alone. A "browser not launched since policy" reason requires observed launch history; test known and unknown history in Tasks 8 and 9.
6. Existing Chrome/Yandex policies and CryptoPro/native hosts must survive agent-managed application, direct external management and mode switching; add foreign-entry, GPO ownership, conflict, no-op, restart and fresh `external_managed` tests in Tasks 6, 8 and 10.

## Tasks

### Task 1: Policy contract and immutable persistence

**Files:** Create `endpoint_contracts/endpoint_policy.py`, `endpoint_server/policy/{models,service,admin_routes}.py`, `endpoint_server/db/migrations/versions/0029_endpoint_policy_dlp_v1.py`; modify `endpoint_server/db/models/__init__.py`, `endpoint_server/main.py`, `endpoint_server/config.py`. Tests in `tests/policy/` and `tests/server/test_migrations.py`.

- [x] Write failing contract tests for bounds, extra-field rejection, digest determinism, audit-only modes, strict `agent_managed | external_managed` browser ownership, default and override resolution, immutability, and audited admin mutation.
- [x] Implement `EndpointPolicyV1`, `PolicyDefinition`, `PolicyVersion`, `PolicyAssignment`, `PolicyDeviceState` and migration with unique `(policy_id,version)` and device assignment constraints.
- [x] Add default-disabled settings and session-authenticated, CSRF-protected paginated Console policy APIs; run focused contract/API/migration tests and `git diff --check`; commit. Local focused result: 101 passed, 7 skipped. PostgreSQL integration tests require `ENDPOINT_TEST_POSTGRES_URL` and remain a release gate.

### Task 2: WSS policy sync and Agent cache

**Files:** Modify `endpoint_contracts/gateway_ws.py`, `endpoint_server/gateway/{protocol,ws_routes}.py`, `pc_agent/transport/{protocol,websocket}.py`, `pc_agent/runtime/{application,lifecycle}.py`; create `endpoint_server/policy/delivery.py`, `pc_agent/policy/{cache,runtime}.py`. Tests in `tests/gateway/`, `tests/policy/`, `pc_agent/tests/transport/`.

- [x] Write failing tests for hello negotiation, old Agent unchanged, delivery on connect/change, ACK status, digest match, atomic cache reload, offline continuity and stale/unsupported states.
- [x] Implement separately typed policy envelopes and server-side effective assignment; apply only validated policy, persist cache atomically in protected Agent data, ACK actual applied state. Until Tasks 3–8 supply sensors, an active policy returns `SENSOR_NOT_READY` and does not replace the last-good cache.
- [x] Run Gateway/Agent tests, contract generation and diff check; commit. Focused result: 642 passed, with generated artifacts passing `--check`. Current Agent `3.2.67` does not advertise the new feature; Windows WSS advertisement starts with a compatible `3.2.68` or newer release in Task 10.

### Task 3: Activity contract and Context retention

**Files:** Create `endpoint_contracts/activity.py` and `endpoint_server/activity/ingestion.py`; modify Context models, policy, canonicalization, retention and projection, Gateway protocol/routes, and generated contracts; add migration `0030_activity_current_projection`. Tests in `tests/activity/`, `tests/context/`, `tests/gateway/`, and migration checks. Agent-side Windows tests belong to Task 5.

- [x] Write failing tests for `ACTIVE/IDLE/LOCKED/DISCONNECTED/UNKNOWN`, idle threshold, bounded foreground/browser identity, semantic dedup, observed-time advance and 24-hour hot history.
- [x] Add typed continuous activity envelope and `activity_v1` current/snapshot handling without Module Operation. Reject query/path/title fields at all entry points.
- [x] Run focused Context/Gateway/retention tests and diff check; commit. Server-side result: 571 passed, 6 skipped; generated contract artifacts pass `--check`. Commit `f0efcf740f772d0d27d00998d35754eb71f1b708`.

The interactive `EndpointUserSensor` and authenticated local IPC are still Task 5. Phase 3 acceptance remains open until a real Windows user-session observation reaches this server path through the Agent.

### Task 4: Shared MV3 browser extension

**Files:** Create `browser_sensor/{manifest.json,background.js,content.js,protocol.js,package.json,README.md,tests/}`. The Node suite checks manifest permissions and forbidden APIs alongside behavior.

- [x] Write failing Node tests for URL normalization, upload MIME categories/count/bytes, paste types without values, heartbeat, family detection, reconnect and 16-KiB bounds; fixture secret marker must never appear in emitted messages.
- [x] Implement one source/manifest using `tabs`, `nativeMessaging` and only justified page access. Content script sends file-input and paste metadata to the service worker; worker connects only to stable native host.
- [x] Run browser unit and permission/security guards; commit. `npm test --prefix browser_sensor`: 9 passed. Commit `b99ea87946f32c629f8531454bde3305c6cf6cb2`.

This is unsigned source only. The bridge, stable signed extension ID, browser policy and live Chrome/Yandex acceptance remain Tasks 5, 6 and 11.

### Task 5: Native bridge and authenticated local IPC

**Files:** Create `pc_agent/platform/windows/{user_sensor,activity_api,browser_bridge,local_ipc}.py`, `pc_agent/{browser_protocol,activity_dispatch}.py`, PyInstaller entry/spec files; integrate service runtime and fixed pipe ACL. Tests in `pc_agent/tests/windows/`, `pc_agent/tests/runtime/`, `tests/packaging/`.

- [ ] Write failing framing/protocol/oversize/unknown-field/wrong-version tests plus pipe DACL, SID/session mismatch, fake-server rejection, disconnect/reconnect and no-network-path tests.
- [ ] Implement unprivileged user-session sampling, native messaging binary framing and bounded ACK; service validates the impersonated pipe client before forwarding activity/browser observations. Keep all device credentials service-side.
- [ ] Test on Windows with a real second user/session where available; run focused suite and diff check; commit.

Native framing, typed ACK, bounded pipe frames, service-SID DACL, OS-backed
client session checks and fake-server rejection are implemented. A safe
user-session sampler and a long-lived, cancellable service pipe listener are
also implemented. On Windows WSS, `RuntimeLifecycle` starts the listener once,
keeps it across reconnects and stops it on exit. A bounded in-memory handoff
retains unsent typed activity observations across WSS reconnects. Until the
approved signed Browser Sensor ID is pinned, browser frames return
`SENSOR_NOT_READY`; no active browser policy is reported as applied. The
Windows MSI now stages the per-session `EndpointUserSensor.exe` with an HKLM Run
entry. Elevated Setup deliberately leaves the User Sensor pending until the
next logon; a safe immediate restart for every active user session remains
open. Signed binary and manifest proof, native Browser Bridge packaging, real
second-session acceptance and end-to-end Windows canary evidence remain open. Do not mark
this task complete or report a live user sensor path yet.

The policy-sensor Windows runtime prepared for 3.2.70 advertises `endpoint.activity.v1` alongside Policy, SecurityEvent and Browser Status. The server requires this negotiated feature for Activity observations; without it, a running User Sensor is rejected at the Gateway. Agent advertisement, Gateway Activity ingestion and WSS contract tests pass together. The 3.2.70 MSI canary rolled back; 3.2.71 is now installed and running on the local Windows canary. Installed User Sensor and second-session acceptance remain open.

The Browser Bridge entrypoint now switches Windows stdio to binary mode and
loads the pinned extension ID embedded in its frozen executable. Its separate
PyInstaller artifact has passed a real executable smoke test and archive check;
the MSI stages it with a single-origin Native Messaging manifest and Chrome
machine registration. The MSI source also registers the same pinned host under
the Chromium key seen in the installed Yandex Browser 26.8.3.1002 binary.
The installed-binary and synthetic Bridge path are recorded below. The actual
extension-to-Agent handshake in both browsers remains an acceptance gate.

On the installed 3.2.72 Windows canary, the packaged User Sensor binary matched
the MSI staging hash and ran in the interactive session after an explicit
start. The Agent accepted its local IPC sample; the server received a fresh
User Sensor observation and projected `activity_v1` with idle and foreground
browser context. The MSI upgrade had stopped the companion without restarting
it. Commit `341a68f` adds the Setup fix and regression tests to restart both
Tray and User Sensor after an interactive upgrade; a new signed release and
upgrade retest are required. This proves the local Activity path on one session, not
second-user/session acceptance or automatic startup after upgrade.

### Task 6: Signed browser release and Browser Integration Policy Applicator

**Files:** Create `browser_sensor/tools/build_release.py`, `endpoint_server/browser_sensor/{models,artifacts,admin_routes}.py`, `endpoint_server/db/migrations/versions/0031_browser_sensor_release.py`, `pc_agent/platform/windows/{browser_policy,browser_policy_helper,browser_policy_helper_entry}.py`, Windows/ALT managed policy templates and `docs/runbooks/browser-sensor-{chrome,yandex,alt,release}.md`; modify server route registration and `pc_agent/policy/runtime.py` to dispatch validated policy ownership changes through the authenticated helper channel. Tests in `pc_agent/tests/windows/test_browser_policy.py`, `pc_agent/tests/policy/` and `tests/browser_sensor/`.

- [x] Write failing tests for deterministic release metadata, stable extension ID, manifest/update XML digest, immutable registry, exact public download route, hash verification and no directory listing. Test that an unpublished or corrupt artifact cannot be served as a valid browser update.
- [x] Write Windows tests for `agent_managed` absent-policy application, no-op repeat, preservation of foreign extension/native-host entries, malformed or externally owned policy conflict, concurrent-change rejection, restart recovery, exact owned-entry hand-off cleanup and `external_managed` no-write after transition. Test Agent-service-SID authentication on every helper request, rejection of an unprivileged caller and of unpinned IDs, URLs and registry paths, and policy-runtime dispatch only after a validated policy update.
- [x] Add a focused fresh `external_managed` applicator test: start with an externally owned force-install entry and no Agent ownership marker; applying the policy must perform no installation-policy write and preserve foreign extensions/native hosts. `test_direct_external_management_never_writes_browser_or_native_host_policy` passes for Chrome and Yandex.
- [x] Build a signed CRX candidate using an external protected key; verify its signature, embedded public key, pinned extension ID, packaged files and immutable local metadata. Publish the verified `0.1.0` release and compare its public HTTPS bytes with the local artifacts.
- [ ] Recheck current official Chrome and Yandex enterprise-policy documentation against the installed versions and their effective policy pages. Validate the existing Chrome `ExtensionSettings` and Yandex `ExtensionInstallForcelist`/`ExtensionSettings` templates without any global native-messaging blocklist.
- [ ] Verify the exact approved Endpoint HTTPS URL in Chrome's managed setting, extension manifest and update XML, including subsequent-update behavior; check Yandex policy precedence and whether an Agent-written local machine value is actually accepted in the domain-managed browser. If not, resolve an official `agent_managed` enterprise-policy mechanism before claiming Task 6 or Foundation complete. Retain `UNKNOWN` browser effectiveness until the live effective-policy and CRX download checks in Task 11.
- [x] Implement the narrowly privileged typed applicator, authenticated Agent-to-helper dispatch, ownership marker and conflict status. Verify merge, ownership and no-op behavior with isolated Windows policy tests; run focused tests and commit. Installed helper and effective machine-policy proof are Task 10, while browser installation and heartbeat are Task 11.

The public extension ID is pinned to a protected external signing key. Release tooling stages only approved MV3 source files, uses installed Chrome to sign the CRX, verifies the CRX3 signature and payload, and emits immutable versioned metadata and update XML. Production migration `0031` is applied. The immutable `0.1.0` release was registered as `cb882bf5-c30b-4122-9432-970b7a12ef29`; its CRX SHA-256 is `0885655086e322d5c13bd90cf4895a8bbc772f28c102c0180447430123392279`. Strict-CA HTTPS reads of update XML, CRX and release metadata matched local bytes. The Windows registry applicator, authenticated fixed-ID helper, typed Agent client and runtime dispatch pass isolated tests. An installed helper start, effective Chrome/Yandex policy, native Bridge handshake and force-install acceptance remain open, so Task 6 stays unchecked.

### Task 7: SecurityEvent ingestion and durable Agent spool

**Files:** Create `endpoint_contracts/security_events.py`, `endpoint_server/security/{models,ingestion,retention,admin_routes}.py`, `endpoint_server/db/migrations/versions/0032_security_events.py`, `pc_agent/security/{spool,runtime}.py`; modify `endpoint_contracts/gateway_ws.py`, Gateway handlers and worker. Tests in `tests/security/`, `pc_agent/tests/security/`.

- [ ] Write failing tests for per-type metadata allowlists, privacy rejection, `(device_id,event_identifier)` idempotency, ACK after commit, crash/replay, replay across policy rotation, <=50 events/64 KiB, 1000-event/5-MiB/24-hour spool bounds, overflow counter and 7..365-day retention (default 30).
- [ ] Implement typed event batch, persisted ACK and protected SQLite spool; no per-observation AuditEvent, Module Operation or raw transport persistence.
- [ ] Run migration, gateway, spool and retention tests; commit.

The typed five-event batch and persisted-event ACK contracts are now in source
and generated JSON Schema. They enforce per-type metadata allowlists, audit-only
severity, unique identifiers, 50-event/64-KiB batch and 2-KiB metadata bounds.
The independent `security_events` table and migration `0032` are now in source,
with a unique `(device_id, event_identifier)` constraint and expiry index.
The Gateway now gates SecurityEvent batches on negotiated Windows support and
the version applied when each event occurred, stages idempotent rows with
per-type enablement and
24-hour event-age checks, commits, then sends the typed ACK. SQLite tests prove
replay deduplication, changed-payload rejection and commit-before-ACK ordering;
the full Gateway suite passed. The worker now deletes expired rows in bounded
transactional batches. The Agent now has a protected SQLite event spool with
1000-event, 5-MiB serialized-payload and 24-hour bounds, durable drop counters,
oldest-first overflow, one in-flight WSS batch and exact-ACK deletion. The
server records each acknowledged application in `policy_applications`; the
Agent waits for the policy ACK frame before replaying queued batches after
reconnect. Tests cover mixed-version replay after rotation and rejection of
events claiming the prior version after the new version was applied. The
server and Agent producer/consumer tests pass. The 3.2.71 Agent is installed and running on the local Windows canary; installed-Agent replay proof remains open after production migration. This is not
yet a verified SecurityEvent pipeline on that Agent.

### Task 8: USB and print audit sensors, browser status and compliance

**Files:** Create `pc_agent/platform/windows/{usb_sensor,print_sensor,browser_status}.py`, `endpoint_contracts/browser_status.py`, `endpoint_server/policy/{browser_status,compliance}.py`, `endpoint_server/db/migrations/versions/0033_browser_status.py`; adjust Agent runtime feature state, Gateway protocol/routes and server DTOs. Tests in `pc_agent/tests/windows/`, `tests/policy/`, `tests/gateway/`.

- [ ] Write failing tests for USB connect/disconnect, serial hashing, print metadata stripping, disabled/audit behavior, availability and server-derived compliance. For each browser independently test detected/absent, running/closed, machine policy configured with effective browser policy unknown, effective policy applied/conflict/external, Native Bridge ready/unavailable, extension never seen/active/stale, and `required=false/true`; heartbeat absence while closed must not itself become installation failure. A fresh `external_managed` policy must report external ownership while Bridge and extension health remain independently observable; a closed never-seen browser is partial, not an installation error. Test known versus unknown launch history after policy application, and a failed hand-off that retains its Agent-owned value and reports conflict without claiming external ownership. Test strict browser-status DTOs, old-Agent negotiation, coalescing, out-of-order reports, separate Chrome/Yandex persistence and missing-report semantics.
- [ ] Implement bounded best-effort USB and print watchers plus per-browser discovery/running, machine-policy owner/state, a separately represented effective-policy observation and Native Bridge health. Investigate a supported browser-side signal for effective enterprise policy; if none is reliable, report `UNKNOWN` rather than inferring effectiveness from the registry or heartbeat. Represent launch-since-current-policy as a bounded known/unknown observation; report unknown whenever monitoring gaps prevent proving that the browser has not launched. Evolve the strict browser-status contract and server projection so `APPLIED` for a machine value cannot be interpreted as browser acceptance. Preserve compatibility with already emitted reports and old Agents. Coalesce bridge heartbeats into a typed WSS status envelope; persist latest per-family status and derive compliance on the server. Mark unsupported/unavailable honestly. Do not implement removable writes without proof of safe reliability.
- [ ] Run Windows and compliance tests; commit.

The Browser Bridge upload/paste route now validates the pinned extension ID,
policy audit mode and a bounded typed payload, then persists the event in the
Agent spool before local ACK. The Agent core build includes the public ID and
the 3.2.71 Agent is now running on the local canary, but live Browser Bridge and DLP acceptance remain open. USB interface
arrival/removal now has a bounded CfgMgr32 notification source, safe event
projection and protected spool handoff. Policy ACK rejects USB audit when
native registration is unavailable. Native registration and a synthetic
callback passed on Windows; physical plug/unplug and on-device retention/health
proof are still required. The local spooler ADD_JOB source now requests only
printer name, user name, total pages and total bytes; its policy gate and
durable-spool handoff are wired. Projection/parser tests and Windows native
subscription start/stop pass. A real disposable print job and installed-browser
proof are still open. The strict Chrome/Yandex status contract, negotiated WSS
frame, per-family current rows, migration `0033`, out-of-order handling and
server-only compliance derivation now pass focused tests. At the earlier
3.2.67 checkpoint, the Agent did not yet send live browser facts. The prepared
policy-sensor
runtime now coalesces accepted Native Bridge heartbeats by browser and applied
policy, inspects registered browser binaries, running processes, policy
ownership and the pinned Native Host manifest without writes, and sends a
two-family WSS report only after the current connection's policy ACK. A
read-only local smoke found Chrome and Yandex detected/running but Native Host
missing in that earlier installation; it is not installed-Bridge or heartbeat
proof. The probe reports `UNKNOWN` when it cannot exclude a per-user browser
installation; a reliable `ABSENT` path remains open. Console projection,
release packaging, installed-browser acceptance and production deployment
remain open. [Yandex's enterprise documentation](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-settings)
says `ExtensionSettings` supersedes other extension policies and Windows policy
effectiveness depends on domain or management-console context. The read-only
inspector recognizes an external `ExtensionSettings` entry, but registry observations alone do not
prove the browser accepted it; Task 11 must inspect the effective policy page.

The shared extension now requests only its own installation type through Chrome's documented permission-free `management.getSelf()` method. The bounded heartbeat carries `admin`, another install type, or `unknown`; the Agent forwards a three-state fact without granting `management` permission. Migration `0034_browser_install_proof` persists that fact with `UNKNOWN` for existing rows. Server compliance now requires administrative installation in addition to a fresh heartbeat and configured machine policy; a registry value or heartbeat alone cannot produce `COMPLIANT`. Console distinguishes configured from browser-confirmed installation. The API behavior in the installed Yandex version, exact effective policy values, signed CRX and full browser-to-Console path remain Task 11 live gates.

The device-status API now exposes a separate server-derived `effective_policy_state`: `APPLIED` requires the current policy ACK, matching machine-policy owner/value, a running detected browser and a fresh extension heartbeat reporting administrative installation; `NOT_APPLIED` requires the same fresh evidence with a non-administrative install type, and all other cases remain `UNKNOWN`. The Console renders this independently from the machine value and no longer recomputes it from raw fields. This is evidence of browser-managed installation, not a reading of the exact effective `ExtensionSettings` or `ExtensionInstallForcelist` value. Task 11 still requires each browser's effective policy page and actual download/Bridge evidence before claiming force-install acceptance.

`last_running_at = null` only means no running process was observed in the available reports; it does not prove the browser never launched after policy application. Compliance now uses `EXTENSION_NEVER_SEEN` for a closed, never-seen browser without launch proof. The more specific `BROWSER_NOT_LAUNCHED` reason remains gated on the reliable launch-since-policy observation required above; Task 8 is still open.

The Windows policy applicator now accepts enabled Activity and browser upload/paste audit only after the local Activity pipe is started, the SecurityEvent spool is open and the approved Bridge extension identity is loaded. USB and print audit still require their live native notification sources. A synthetic Windows runtime test proves that a fully ready policy receives `APPLIED`; missing components still fail before browser-policy writes. This is local readiness, not proof that the per-user sensor, browser extension, physical USB/print sources or server ingest work on an installed Agent. Fleet-wide Activity/DLP `ACTIVE` status must come from fresh sensor observations or a separate bounded health report, never from policy ACK alone.

USB availability now requires both a registered PnP notification and a live dispatch worker. A stale registration with a dead worker fails readiness and must be stopped before restart; the policy applicator cannot use that state as USB audit proof. Runtime health and installed-device event acceptance remain open.

The installed 3.2.72 Bridge binary matched its MSI staging hash. Two bounded
synthetic Native Messaging sessions through that binary produced server-side
`BROWSER_PASTE` and `BROWSER_UPLOAD` SecurityEvents with safe metadata and
30-day expiry. Their event ACKs were `OK`, but the preceding Hello ACK was
`IPC_UNAVAILABLE`: the installed Agent accesses an `install_type` field absent
from `BrowserHelloV1`. A red test reproduced the exception; commit `db427bb`
fixes it and adds a regression test. Rebuild and retest Hello with
the next signed Agent; synthetic host traffic does not prove browser-extension
action capture.
Chrome has produced a fresh administrative-install heartbeat through the
installed path. Yandex has no extension heartbeat, so its installation and
Browser Bridge path remain unverified.

### Task 9: Russian Console

**Files:** Create `webapp/src/SecurityPage.tsx` and typed client DTOs; modify `webapp/src/{App,FleetPages,api,styles.css}` and `endpoint_server/console/` routes/projections. Tests in `webapp/src/`, `webapp/e2e/`, `tests/server/`.

- [ ] Write failing tests for policy version/assignment controls, fleet compliance pagination/filtering, separate Chrome/Yandex machine-policy ownership and effective application state, a configured-but-unverified policy shown as `настроена` with unknown browser effectiveness, and `применена` only after browser-side confirmation. Cover Russian labels for detected/applied/Native Bridge/never-seen/active/stale/conflict/external/closed, show the reason "браузер не запускался после применения политики" only with supporting launch evidence, show unknown history honestly, preserve last version/heartbeat when closed, and cover device activity, safe event list/detail, release metadata and no unsupported fake-active status.
- [ ] Add `Политики и DLP`, bounded admin APIs and device tabs with Russian labels/empty/error states; use existing session/CSRF and safe DTO conventions.
- [ ] Run frontend unit, Playwright E2E, production build and Console API tests; commit.

The first device-detail slice has an authenticated, bounded read-only policy/browser-status projection and a Russian tab with separate Chrome and Yandex facts. Server compliance is gated by the current process's active Agent connection and `endpoint.browser-status.v1`; a disconnected or older Agent cannot appear ACTIVE, while the last observed extension version and heartbeat remain visible. The server currently enforces a single Gateway worker through `assert_single_gateway_worker()` and `GatewayWorkerLease`; verify that deployment invariant at acceptance, and use shared presence/capability evidence if multi-worker hosting is introduced. A bounded authenticated SecurityEvent list/detail API and Russian `/admin/security` page now filter by period, device, user, channel, type, severity and domain; stored metadata is revalidated before display. Console Playwright passed with mocked SecurityEvent data on desktop and a 390-pixel mobile viewport, including a mobile width check; this is not Browser Sensor/Agent acceptance.

The Console now reads bounded policy summaries, immutable version details and the current default assignment through authenticated admin APIs. Its typed form creates a policy from disabled defaults or appends a new version; selected versions can be assigned as default or to a device through the existing audited routes. A newly created version stays selected even while the older version remains the default. Device browser cards label an Agent-written registry value as configured and leave browser effectiveness unconfirmed until stronger evidence exists. Installed-Agent event proof and deployment remain open, so Task 9 is still incomplete.

The fleet policy table now reads a bounded authenticated API that derives overall compliance and Activity, Browser and DLP sensor states from the current Gateway connection, effective assignment, policy acknowledgement and fresh reports. Filters for Compliant, Partial, Non-compliant, Stale and Unsupported are applied before pagination; the filtered total counts all matching devices. The backend reads devices and evidence in fixed-size batches for this dynamic filter. The Russian Console shows policy and applied versions, last acknowledgement, Agent version and individual sensor states, with search, empty/error states and mobile horizontal table scrolling. Focused API tests cover all five statuses, per-device overrides and literal search; the full Python suite passed (`2229 passed, 41 skipped`), and generated contract artifacts remain current. Frontend unit tests (`39 passed`), the production build and disposable Playwright desktop/mobile checks passed. This is Console behavior only; live installed-Agent evidence and production acceptance remain open.

The Device Detail `Активность` tab now reads a separate authenticated, bounded current-activity projection. It shows user, session state, idle time, foreground app/category, browser/domain and last observation, with distinct offline, stale, empty and error states; raw snapshots and window titles are not rendered. The real API passed its focused tests, the Console unit suite passed, and a disposable Playwright login-to-device flow passed on desktop and 390-pixel mobile. Full Python tests passed (`2198 passed, 41 skipped`) at that checkpoint; generated contract artifacts were current. Live managed-Agent Activity remains open, so Task 9 stays unchecked.

The `Политики и DLP` page now reads the existing authenticated current Browser Sensor release projection and displays the version, pinned extension ID, protocol, artifact SHA-256, minimum Agent, source revision, publication time and public update/package URLs. It renders an explicit unpublished or load-error state and never displays signing material. Frontend unit tests (`36 passed`), the production build and a disposable Security Console Playwright flow passed on desktop and 390-pixel mobile with a mocked release. Actual published-release and managed-browser acceptance remain Task 11 gates.

### Task 10: Windows/ALT packaging and release

**Files:** Modify `packaging/windows/{build-msi,build-update-zip}.ps1`, `packaging/windows/wix/{Services,Components}.wxs`, `packaging/alt/`, `pc_agent/version.py`, release manifests, architecture/package tests. Include the fixed SYSTEM policy helper and strict service-SID channel while retaining the Agent as LocalService.

- [ ] Write failing packaging tests for installed user sensor/bridge/policy helper, native-host registration for both browsers, exact origin, no global native-messaging blocklist, service-SID ACL, upgrade/ownership preservation, direct `external_managed` no-write and old-Agent rollback behavior; add ALT package tests only for supported paths. Verify the installed MSI's helper identity, binary location, authenticated Agent-to-helper channel and effective machine policy on a Windows test device.
- [ ] On the installed Windows test device, snapshot foreign extension policies and Native Messaging hosts before and after MSI install/upgrade. Verify the helper leaves them unchanged, a repeated identical policy performs no installation-policy write, and a failed ownership merge reports `POLICY_CONFLICT` without partial writes.
- [x] Build the fixed `EndpointBrowserPolicy.exe` alone and prove a temporary, correctly configured Windows SCM service reaches `Running` and stops cleanly. The LocalSystem service started, an interactive caller received pipe access denied (Win32 5), and the temporary service was stopped and deleted. The same check against the exact MSI-bound helper binary also reached `Running` as LocalSystem and denied the interactive caller.
- [x] Retain the retired 3.2.70 release as immutable failure evidence. Build 3.2.71 and, after the helper ACL defect surfaced in its pilot, build 3.2.72 from the fixed source with a clean runtime stage, pinned provenance, signed MSI/Setup and immutable ZIP. Verify source revision, every ZIP member hash and Authenticode validity.
- [ ] Supersede immutable 3.2.73 with a new version containing the bounded helper-start retry. Build a clean runtime stage, provenance, signed MSI/Setup and immutable ZIP; test installed upgrade, both companion processes, Hello ACK, first policy ACK without manual service restart, WSS readiness and rollback before registering a Setup release. Do not register 3.2.72 or 3.2.73 Setup as the completed Foundation candidate.
- [ ] Run full Python suite, contracts, Alembic, Windows packaging, frontend, browser tests, provider-release-gate and diff check; commit.

The signed 3.2.70 MSI/Setup was registered as production release `bacb2f60-acb2-49ba-806d-5a94b09752d2`, then failed the local Windows canary: Windows SCM repeatedly timed out starting `EndpointBrowserPolicy.exe` because its frozen entry script used relative imports. Setup exited 21 and MSI rolled back to installed 3.2.65 with runtime 3.2.67. The Agent was restarted and strict-WSS preflight passed; identity hashes and foreign Chrome Native Messaging entries matched the preinstall snapshots. The broken 3.2.70 Setup release was retired in the production registry and must not be reused. Commit `2a393594e5469292c55d7833f033c0cc772b424c` changed the helper entry to absolute imports and added a direct-entry regression test. The 3.2.70 package had valid Authenticode signatures but no timestamp. No installed package, browser force-install, or Agent upgrade acceptance is inferred from the rolled-back attempt.

The corrected frozen helper passed both standalone and exact MSI-bound SCM smoke checks. Agent 3.2.71 source `5de1399617d78174347537993952c938bc387cfb` and initial-runtime provenance were pinned in commits `5de1399` and `a86d18a`. The clean stage contained 2543 files; its tree SHA-256 was `1a5f67569ffa5eecc37bf56ab0c87b4a25a45e38d9ff9ec15f297a795749630e`. The signed 3.2.71 MSI SHA-256 is `d1b7dd7ea7f1029c06346435868a512fe65c1fcd8ba7b703bbcd2968eeab7f00`, the signed Setup SHA-256 is `72fc397dea24e8dddc386904dd26eb1d6b3cf258bca35814ff6483a329bd92f3`, and the immutable update ZIP SHA-256 is `21064b721b68d7b1e1f8b7890c1096dc1cee1c6ca3d581d08b1454b77dcfa627`. Both Authenticode signatures validated locally but have no trusted timestamp. The complete Python suite passed (`2235 passed, 41 skipped`); focused Agent (`66 passed`) and packaging (`55 passed`) suites and Ruff passed. The signed Setup installed successfully on the local Windows canary with `EndpointAgent` and `EndpointBrowserPolicy` running. The after-install preflight passed and preserved the enrolled identity and all seven pre-existing Chrome Native Messaging registry sections. Live managed browser policy application remains unverified.

The production registry accepted the 3.2.71 ZIP as build `ddfd8ef7-0dd8-4af2-8981-0b2a2c8ec4a3` after hash and device-scope checks. A rollout limited to the local Windows device `c450fc70-63e6-4c2b-baf6-7de79820d63f` completed with server report `applied|3.2.71|post_restart_handshake_confirmed` and strict-WSS canary status. Its selected runtime is marked MSI-owned: the updater compared the downloaded ZIP contents with the identical 3.2.71 MSI runtime already on disk, reused that tree, and switched the selector. The installed-runtime preflight passed with MSI package identity. This demonstrates the rollout/control-plane path and runtime byte equivalence, but not extraction of a distinct ZIP runtime directory. A later update to a version absent from the MSI is still needed to exercise that path. Neither the 3.2.71 nor the 3.2.72 Setup release is registered; register the current candidate only after its release gate. The retired 3.2.70 release remains immutable failure evidence.

The device-scoped `Municipal Default v1 (Policy DLP pilot)` assignment first produced `BROWSER_POLICY_HELPER_UNAVAILABLE` on 3.2.71. Isolated Windows checks identified the three missing rights above. The fixed 3.2.72 candidate is pinned to source `7df39343b2e42dbc56e4eac8f0248c765d9efe14`; its 2543-file runtime tree SHA-256 is `ab7168ac0125664aff42206d9a1b22788d5d3eaaaaafafe364a8e93e2355f03a`. Signed MSI SHA-256 is `1e2ed31f0031d7aa3a669a46352475e600934d1baf85be559a67997da6d84841`, signed Setup SHA-256 is `24906af88d6b7ef0c040e1ee5758420bb2b1731166606d27c9c8687b373fe598`, and verified ZIP SHA-256 is `ee624d0284ab57f65d58e64d1effc353e891918721876f9cdd6285fe3f273828`. Both signatures are valid locally without a trusted timestamp. The full Python run with the locally installed Agent running had three pipe-collision failures; with it stopped, those three passed and the run had `2233 passed, 41 skipped` with four installer tests failing because the service was stopped. Those four passed after restart. The split result covers the environment-dependent tests but is not a single green full-suite run.

The signed 3.2.72 Setup installed on the local canary; its installer log recorded `UPDATED/SERVICE_RUNNING`. A fresh preflight validated the MSI-owned 3.2.72 selector, signed MSI identity and strict Gateway WSS as `READY`. The newly installed helper process runs as LocalSystem and exposes the narrow Agent process-query ACE. The first policy ACK during service replacement was `ERROR`; after restarting the Agent with the fresh helper, the server recorded `APPLIED` at `2026-09-25 11:00:08 UTC` with the unchanged policy digest. Chrome and Yandex machine policy entries are Agent-owned and `APPLIED`; these observations do not prove browser-effective installation. Chrome has an earlier `0.1.0` administrative-install heartbeat, but it was stale at this ACK; Yandex has no extension heartbeat. Both browser effective-policy pages, fresh bridge heartbeat, update download and remaining Task 11 scenarios still require live proof.

After that ACK, Chrome produced a fresh administrative-install heartbeat and
the interactive User Sensor produced live Activity. The 3.2.72 Bridge's Hello
failure and the Setup companion-restart defect were found in installed-binary
checks. Source fixes `db427bb` and `341a68f` are committed but absent from the
immutable installed 3.2.72 candidate. Test isolation commit `6725ccb` lets
WSS identity tests run while the installed Agent owns the machine pipe. The
complete Python 3.14.3 suite passed with the installed Agent running:
`2239 passed, 41 skipped` in 374.62 seconds. Ruff and 111 focused tests passed.
The next candidate must also confirm that the installed Bridge returns an
`OK` Hello ACK and that Setup starts User Sensor automatically.

The clean 3.2.73 stage was pinned to source
`b70e6693ccc7a78452074816a1f8c2a6a07e3906` in provenance commit
`0f2f8a5`. Its 2543-file runtime tree SHA-256 is
`cf4128c653d24b719a0218d1c7c98ab1b3aa1d98c9fb56b817089c372e0aa288`.
The signed MSI SHA-256 is
`adb2082869df1e6052d51fd77a9a2e050263474b64dc52ce81ef4a46b4b64c37`,
the signed Setup SHA-256 is
`92557e962c44dff814dc97a8b3eb18999031cef297dd67e69a6d26f141f151a2`,
and the verified immutable ZIP SHA-256 is
`d052fc96c4e5cac63958dfaea535b67f11b32483c4c81492b62e9ae06e176709`.
Both signatures validated locally without a trusted timestamp. Packaging
tests passed (`94 passed, 1 skipped`). The 3.2.73 Setup updated the local
Windows canary; installer log reported `UPDATED/SERVICE_RUNNING`, both Tray
and User Sensor started in the active session, and the installed-runtime
preflight returned `READY`. After manually restarting the Agent, the
installed Bridge's synthetic Hello returned `OK` and the server recorded a
policy ACK as `APPLIED`. This confirms the two installed-binary fixes but not
live browser capture. The first ACK after installation was instead
`BROWSER_POLICY_HELPER_UNAVAILABLE`: the Agent started about 1.5 seconds
before its helper. Source commit `aec846e` now retries only a missing/busy
helper pipe for a bounded period; its focused tests passed (`16 passed`),
but that fix is absent from installed 3.2.73. Prove the first ACK with a
fresh signed version before release registration.

The next canary is 3.2.74, with the bounded helper-start retry in source
commit `3a984720ac96be67b685679f6e7d151211f788b5` and pinned provenance
commit `d8522b4bad65018ce9a52275128e4e5e32b7f3c3`. Its 2543-file stage
tree SHA-256 is
`772add8e56ef211e20c079c47d7084c9cb8e49a2729959b9381928b8c8ead73c`.
The signed MSI SHA-256 is
`f0a492f522dc423df43d368fa59dd87ba46ec633d422862eb0605f93994b9294`,
the signed Setup SHA-256 is
`0789653a65e642993d38c0ac88a7374b99c0d9ac01596381ed27351b910cd03a`,
and the 2544-entry verified update ZIP SHA-256 is
`ac2e06e6c2a8aa6f986cb20a516b3629bfd549a7556328065ef3a02f700c66d6`.
Both Authenticode signatures are valid locally without a trusted timestamp.
The full Python suite passed (`2243 passed, 41 skipped`), packaging tests
passed (`94 passed, 1 skipped`), and Browser Sensor Node tests passed
(`12 passed`). Before and after Setup, the installed-runtime preflight was
`READY`; the exact signed 3.2.73 rollback MSI/Setup were retained and
hash-verified. The local 3.2.74 Setup logged `UPDATED/SERVICE_RUNNING` and
the selector names 3.2.74 with the pinned stage revision. The first server
policy ACK after install was `APPLIED` at `2026-09-25 12:45:53 UTC` with no
manual Agent restart; the installed Bridge returned a synthetic Chrome Hello
ACK `OK`. During this run, `Start-Process -Wait` kept waiting for Setup's
long-lived companion descendants; interrupting that wait terminated Tray
and User Sensor. Both were restored manually in the interactive session.
This invocation does not prove companion auto-start for 3.2.74; a separate
uninterrupted upgrade/restart check and rollback remain open. Do not register
the Setup release or call the Foundation candidate complete on this evidence.

### Task 11: Live Windows acceptance and limited pilot

**Files:** `docs/architecture/endpoint-policy-dlp-foundation-v1.md`, `PLANS.md`, evidence under a non-secret release report path.

- [ ] Validate production disk and backup, migration and immutable server release; verify strict CA/hostname HTTPS, WSS, service logs and previous release marker.
- [ ] Canary the next signed Agent on the local test workstation, then one IT and 1–3 pilot workstations only after exact rollback artifacts. Reconfirm installed browsers at the gate; both Chrome and Yandex are installed on the reference workstation as of 2026-09-25, so both require live proof. Use a disposable clean browser profile or separate test device to establish the extension-absent starting state without altering the user's active profile. Assign `Municipal Default v1` with `browser_sensor.required=true` and `deployment_mode=agent_managed`; prove the Agent-owned machine-policy value and each browser's effective force-install policy separately, then browser download of the approved signed CRX over Endpoint HTTPS, successful Bridge Hello and heartbeat, and `PENDING→APPLIED→COMPLIANT` in both browsers. An absent browser on another pilot device is an explicit untested gap, not proof of same-CRX support. Exercise activity, physical or disposable USB/print actions and browser upload/paste actions, Console projection, browser-closed semantics, idempotent reapply, browser/Agent restart, upgrade, `external_managed` hand-off with no subsequent Agent policy writes or removal of foreign entries, rollback and reapply. Keep synthetic Bridge events as transport evidence only. Separately start from a pre-existing externally owned force-install entry with no Agent marker; prove direct `external_managed` performs no installation-policy write while Bridge heartbeat and Console status work. Inspect effective policy pages and unrelated corporate extensions/native hosts before and after each ownership change.
- [ ] At that gate, record per browser: version, domain/management prerequisite, policy value and ownership, effective policy status, signed CRX ID/version and HTTPS download source, Native Host registration, Bridge connection, Agent heartbeat and Console state. Prove a later extension update still uses Endpoint HTTPS. Keep machine-policy configuration, browser acceptance and extension activity as separate evidence; a registry write or policy ACK alone cannot yield `ACTIVE`/`COMPLIANT`. Check a closed browser retains last-known version/heartbeat without an installation error.
- [ ] Search Agent logs, browser output, server DB, SecurityEvent, Audit and Context for a synthetic secret marker. Record negative result and browser version/package proof. If a dependency is unavailable, record the exact gap and do not claim Foundation complete.

Production server deployment has partial evidence for this gate: the verified pre-deploy PostgreSQL backup is `/var/backups/endpoint-platform/pre-policy-dlp-20260925T083415Z.dump`; the immutable release under `/opt/endpoint-platform/releases/endpoint-platform-abdd5c7ef596` is current, Alembic reached `0035_policy_sensor_health`, API/worker/Nginx/PostgreSQL were active, and strict-CA/hostname HTTPS `/healthz` returned 200. The previous-release marker points to `endpoint-platform-1dc3ad3acfc5`. This does not prove a live Agent WSS policy exchange or Windows Browser Sensor acceptance. Recheck the live services and rollback marker at the final gate.

The local device subsequently acknowledged its assigned policy as `APPLIED`
over WSS; live User Sensor Activity, Chrome heartbeat and synthetic Bridge
SecurityEvents reached the server. These observations do not prove
`agent_managed` force-install from an absent state, live browser upload/paste
capture, USB/print acceptance, Console `COMPLIANT` or Yandex acceptance.
Yandex `ExtensionInstallForcelist` exists as an Agent-owned machine value, but
an isolated browser profile did not install the approved extension and no
Yandex heartbeat arrived. Do not replace the user's existing browser or use
profile installation as an implicit workaround.
The operator has confirmed that only the currently installed Yandex Browser
is available; neither a separate Browser for Organizations package nor its
management Console is available. The operator's `browser://policy` screenshot
shows the Agent-owned `ExtensionInstallForcelist` value with the approved ID
and Endpoint HTTPS update URL, source `Платформа`, scope `Локальный компьютер`,
mandatory level and status `OK`. The update XML and referenced CRX returned
HTTP 200 under strict CA/hostname TLS from the workstation; the XML names
version `0.1.0`, and the CRX has a `Cr24` header. These checks establish
browser policy recognition and server artifact availability, not browser
download or installation. The operator also opened the XML successfully in
Yandex Browser, while its `browser://extensions` page has no Endpoint Browser
Sensor entry. Inspect browser installation diagnostics and the CRX request,
then obtain a Yandex Bridge heartbeat before closing the gate. Yandex's
published policy documentation says Windows force-install requires domain
policy or its management Console; the current `OK` policy display does not
yet prove that the local Agent-written value triggers installation. Do not
assume that an unavailable corporate package is a valid completion path.
The production Nginx access log through `2026-09-25 12:20:39 UTC` contains
Chrome's policy-driven update XML and CRX requests, plus the operator's
manual Yandex XML request, but no Yandex policy-driven update or CRX request
in that log. This narrows the Yandex gap to policy enforcement/request
initiation before the Endpoint artifact service; inspect browser diagnostics
before attributing the cause to a specific management prerequisite.

### Task 12: Final release audit

- [ ] Inspect complete branch diff, migration/config/contract effects, untracked files and remote ancestry. Run `git diff --check` and required gates against frozen SHA.
- [ ] Review privacy and architectural invariants, publish only verified artifacts, report start/end/remote SHA, signed hashes, exact test commands, production evidence and gaps. Do not mark the goal complete until one managed Windows endpoint demonstrates the specification's Definition of Done.
