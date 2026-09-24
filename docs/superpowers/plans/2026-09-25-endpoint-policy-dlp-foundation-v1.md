# Endpoint Policy & DLP Foundation v1 Implementation Plan

> **For agentic workers:** Execute the checked tasks in order; each task ends with focused tests and a review of the complete diff. The supplied specification is the authority for scope and acceptance.

**Goal:** Deliver server-owned continuous Policy, Activity, browser and audit DLP sensors, safe event storage, and Russian Console status on a managed Windows canary.

**Architecture:** Keep Policy and sensors outside Module Platform. The authenticated Gateway WSS carries separately typed policy, activity and security-event messages only for Agents that advertise support. The LocalService Agent validates data from a per-user sensor and Chromium native messaging bridge through a local named pipe. In `agent_managed` mode, a separate fixed SYSTEM component applies only the approved extension's machine-level browser policy; `external_managed` mode makes no installation-policy write. Server storage keeps immutable policy versions, a current activity projection, and expiring typed security events.

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
5. **One CRX:** Chrome and Yandex officially support managed force-install from an update URL. A single signed CRX is the target; same-package acceptance is unproven because this workstation currently has Chrome 153 but no Yandex installation. Do not claim compatibility until both installed browsers pass a managed-policy handshake with the identical CRX. In `agent_managed`, begin with the extension absent and prove Agent-driven force-install; in `external_managed`, Agent only reports observed state.
6. **Stable ID:** Generate/store a dedicated signing private key outside Git in protected operator storage, derive and pin the Chromium extension ID from its public key, and fail release build if ID changes. The native host manifest lists exactly that `chrome-extension://<id>/` origin.
7. **Artifacts:** Use the existing `artifact_root`, digest verification and immutable metadata pattern, with public fixed routes for the signed CRX and update XML over `endpoint.sosnadmin.local`. No path-derived directory access or directory listing. The approved extension ID and update URL are typed server-owned policy inputs to the applicator, never free registry strings from an endpoint user.
8. **Activity APIs:** In the user session, use `GetLastInputInfo` plus `GetTickCount64`, `WTSRegisterSessionNotification`/`WM_WTSSESSION_CHANGE`, `GetForegroundWindow` + `GetWindowThreadProcessId`, and process basename only. `GetLastInputInfo` is session-specific, which is why the service cannot poll it in session 0. Never read titles or command lines.
9. **USB/print APIs:** Use a service-side `CM_Register_Notification` (or existing service event callback where proven) for USB arrivals/removals and bounded device properties; use `FindFirstPrinterChangeNotification`/`FindNextPrinterChangeNotification` for print jobs, discarding document title and spool content before serialization.
10. **Reliable scope:** USB lifecycle, spooler print notifications, browser file-input selection and paste occurrence are feasible without a kernel driver, subject to lab proof. Removable writes and network shares are deferred unless a tested, privacy-safe OS mechanism is found; no driver, blocking or content capture is in v1.

Relevant official documentation: [Chrome ExtensionSettings](https://support.google.com/chrome/a/answer/9867568?hl=en), [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [Yandex force-install](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist), [Yandex native messaging allowlist](https://browser.yandex.ru/support/browser-corporate/ru/policy/native-messaging-allowlist), [GetLastInputInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo), [WTS session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification), [device notifications](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerdevicenotificationa), [print notifications](https://learn.microsoft.com/en-us/windows/win32/printdocs/findnextprinterchangenotification).

### Browser deployment ownership and privilege boundary

The supplied addendum changes only Browser Sensor deployment ownership. `browser_sensor.deployment_mode` is a strict `agent_managed | external_managed` enum. The current MSI installs `EndpointAgent` as **LocalService**, so its runtime cannot write HKLM browser policy. Keep that account and add a narrowly privileged, signed, fixed-function helper/service controlled over an authenticated local channel by the Agent service SID. It may write only the pinned Endpoint extension ID and approved HTTPS update URL in Chrome/Yandex machine policy, and its own ownership marker; it must reject arbitrary registry paths, browser IDs and URL values. No entire-Agent elevation.

Chrome `ExtensionSettings` is preferred; Yandex `ExtensionInstallForcelist` or `ExtensionSettings` is selected after verifying actual installed version and effective policy. Before any registry write, read existing policy and ownership marker, parse/validate the complete value, preserve unrelated entries, and compare the pre-write value immediately before replacement. If the value is GPO/cloud-owned, malformed, concurrently changed or incompatible, fail closed as `POLICY_CONFLICT`. Reapplication of identical state is a no-op. On transition to `external_managed`, the applicator may remove only its own exact, unchanged extension entry and marker; it preserves every foreign entry and reports conflict if ownership is uncertain. After hand-off, `external_managed` makes no installation-policy write. Native-host registration remains MSI-owned; do not set `NativeMessagingBlocklist = *` because other corporate hosts may be in use.

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
5. Browser closed, browser absent, extension never seen and extension stale must be distinct per browser, with no false installation failure on heartbeat absence alone; add state tests in Tasks 8 and 9.
6. Existing Chrome/Yandex policies and CryptoPro/native hosts must survive agent-managed application and mode switching; add foreign-entry, GPO ownership, conflict, no-op and restart tests in Tasks 6 and 10.

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

### Task 6: Signed browser release and Browser Integration Policy Applicator

**Files:** Create `browser_sensor/tools/build_release.py`, `endpoint_server/browser_sensor/{models,artifacts,admin_routes}.py`, `endpoint_server/db/migrations/versions/0031_browser_sensor_release.py`, `pc_agent/platform/windows/{browser_policy,browser_policy_helper}.py`, Windows/ALT managed policy templates and `docs/runbooks/browser-sensor-{chrome,yandex,alt,release}.md`; modify server route registration. Tests in `pc_agent/tests/windows/test_browser_policy.py` and `tests/browser_sensor/`.

- [ ] Write failing tests for deterministic release metadata, stable extension ID, manifest/update XML digest, immutable registry, exact public download route, hash verification and no directory listing.
- [ ] Write failing Windows tests for `agent_managed` absent-policy application, no-op repeat, preservation of foreign extension/native-host entries, malformed or externally owned policy conflict, concurrent-change rejection, restart recovery, exact owned-entry hand-off cleanup and `external_managed` no-write after transition. The helper must reject unpinned IDs, URLs and registry paths.
- [ ] Build a signed CRX using an external protected key. Publish metadata separately from bytes; generate Chrome `ExtensionSettings` and Yandex `ExtensionInstallForcelist`/`ExtensionSettings` templates without any global native-messaging blocklist. Implement the narrowly privileged typed applicator with an ownership marker and conflict status.
- [ ] From an extension-absent managed Windows device, let Agent apply machine policy, then verify browser downloads the *same CRX* in Chrome and Yandex. Record actual versions, effective policy, handshake and unrelated policy preservation. If one package fails, document evidence and create separate artifacts from the same source; commit.

### Task 7: SecurityEvent ingestion and durable Agent spool

**Files:** Create `endpoint_contracts/security_events.py`, `endpoint_server/security/{models,ingestion,retention,admin_routes}.py`, `endpoint_server/db/migrations/versions/0032_security_events.py`, `pc_agent/security/{spool,runtime}.py`; modify `endpoint_contracts/gateway_ws.py`, Gateway handlers and worker. Tests in `tests/security/`, `pc_agent/tests/security/`.

- [ ] Write failing tests for per-type metadata allowlists, privacy rejection, `(device_id,event_identifier)` idempotency, ACK after commit, crash/replay, <=50 events/64 KiB, 1000-event/5-MiB/24-hour spool bounds, overflow counter and 7..365-day retention (default 30).
- [ ] Implement typed event batch, persisted ACK and protected SQLite spool; no per-observation AuditEvent, Module Operation or raw transport persistence.
- [ ] Run migration, gateway, spool and retention tests; commit.

### Task 8: USB and print audit sensors, browser status and compliance

**Files:** Create `pc_agent/platform/windows/{usb_sensor,print_sensor,browser_status}.py`, `endpoint_contracts/browser_status.py`, `endpoint_server/policy/{browser_status,compliance}.py`, `endpoint_server/db/migrations/versions/0033_browser_status.py`; adjust Agent runtime feature state, Gateway protocol/routes and server DTOs. Tests in `pc_agent/tests/windows/`, `tests/policy/`, `tests/gateway/`.

- [ ] Write failing tests for USB connect/disconnect, serial hashing, print metadata stripping, disabled/audit behavior, availability and server-derived compliance. For each browser independently test detected/absent, running/closed, policy applied/conflict/external, Native Bridge ready/unavailable, extension never seen/active/stale, and `required=false/true`; heartbeat absence while closed must not itself become installation failure. Test strict browser-status DTOs, old-Agent negotiation, coalescing, out-of-order reports, separate Chrome/Yandex persistence and missing-report semantics.
- [ ] Implement bounded best-effort USB and print watchers plus per-browser discovery/running, effective policy owner/state and Native Bridge health. Coalesce bridge heartbeats into a typed WSS status envelope; persist latest per-family status and derive compliance on the server. Mark unsupported/unavailable honestly. Do not implement removable writes without proof of safe reliability.
- [ ] Run Windows and compliance tests; commit.

### Task 9: Russian Console

**Files:** Create `webapp/src/SecurityPage.tsx` and typed client DTOs; modify `webapp/src/{App,FleetPages,api,styles.css}` and `endpoint_server/console/` routes/projections. Tests in `webapp/src/`, `webapp/e2e/`, `tests/server/`.

- [ ] Write failing tests for policy version/assignment controls, fleet compliance pagination/filtering, separate Chrome/Yandex policy ownership and application state, Russian labels for detected/applied/Native Bridge/never-seen/active/stale/conflict/external/closed, reason for a browser not launched after policy application, preserved last version/heartbeat when closed, device activity, safe event list/detail, release metadata and no unsupported fake-active status.
- [ ] Add `Политики и DLP`, bounded admin APIs and device tabs with Russian labels/empty/error states; use existing session/CSRF and safe DTO conventions.
- [ ] Run frontend unit, Playwright E2E, production build and Console API tests; commit.

### Task 10: Windows/ALT packaging and release

**Files:** Modify `packaging/windows/{build-msi,build-update-zip}.ps1`, `packaging/windows/wix/{Services,Components}.wxs`, `packaging/alt/`, `pc_agent/version.py`, release manifests, architecture/package tests. Include the fixed SYSTEM policy helper and strict service-SID channel while retaining the Agent as LocalService.

- [ ] Write failing packaging tests for installed user sensor/bridge/policy helper, native-host registry for both browsers, exact origin, no global native-messaging blocklist, service-SID ACL, upgrade/ownership preservation and old-Agent rollback behavior; add ALT package tests only for supported paths.
- [ ] Select next Agent version from current registry; build signed MSI/Setup and immutable ZIP with source revision, all member hashes, WSS startup proof and verified rollback artifact.
- [ ] Run full Python suite, contracts, Alembic, Windows packaging, frontend, browser tests, provider-release-gate and diff check; commit.

### Task 11: Live Windows acceptance and limited pilot

**Files:** `docs/architecture/endpoint-policy-dlp-foundation-v1.md`, `PLANS.md`, evidence under a non-secret release report path.

- [ ] Validate production disk and backup, migration and immutable server release; verify strict CA/hostname HTTPS, WSS, service logs and previous release marker.
- [ ] Canary Agent update on the local test workstation, then one IT and 1–3 pilot workstations only after exact rollback artifacts. Begin without the extension, assign `Municipal Default v1` with `deployment_mode=agent_managed`, and prove Agent-owned policy application, browser force-install/download, Bridge handshake and `PENDING→APPLIED→COMPLIANT` in Chrome and Yandex. Exercise activity, synthetic USB/print/upload/paste, Console projection, browser-closed semantics, idempotent reapply, browser/Agent restart, upgrade, `external_managed` no-write switch, rollback and reapply.
- [ ] Search Agent logs, browser output, server DB, SecurityEvent, Audit and Context for a synthetic secret marker. Record negative result and browser version/package proof. If a dependency is unavailable, record the exact gap and do not claim Foundation complete.

### Task 12: Final release audit

- [ ] Inspect complete branch diff, migration/config/contract effects, untracked files and remote ancestry. Run `git diff --check` and required gates against frozen SHA.
- [ ] Review privacy and architectural invariants, publish only verified artifacts, report start/end/remote SHA, signed hashes, exact test commands, production evidence and gaps. Do not mark the goal complete until one managed Windows endpoint demonstrates the specification's Definition of Done.
