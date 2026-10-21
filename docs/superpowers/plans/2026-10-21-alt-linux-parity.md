# ALT Linux Agent parity implementation plan

**Goal:** A stable ALT 11 Agent using the existing Gateway, Context, Policy,
Activity and SecurityEvent contracts, accepted on real KDE sessions.

**Architecture:** Preserve the unprivileged system Core and root update worker.
Add Linux adapters under `pc_agent/platform/linux`, a separate session sensor,
and authenticated Unix socket ingress. Keep shared business rules and WSS.

**Spec:** User-supplied ALT Linux 11 task, sections 1–16, 2026-10-21.
Execution is explicitly authorized without intermediate approval stops.

## Constraints and acceptance

- No production rollout, monitoring-policy changes, mass deployment or TLS bypass.
- Preserve AD configuration, device identity, user state and unrelated local work.
- Content-free observations only; no titles, file contents, document names or keys.
- Report unavailable sources honestly; unit tests do not establish live acceptance.
- Current main: `c22024492dbb6b12fe5760c54868d18987b668f2`, Agent 3.2.121.
- Original checkout is dirty; use `codex/alt-linux-parity` in its managed worktree.

## A — Core and RPM

- [x] Inspect GitNexus baseline, source, dependencies and available hosts.
- [x] Build current immutable Core/launcher and RPM on ALT/Python 3.12.
- [ ] Reproduce/fix runtime and package failures with focused regression tests.
- [x] Install/register the reference pilot; verify strict HTTPS, WSS, scheduled
  baseline/health/network and inventory reflected in Console.
- [ ] Verify installation/upgrade preserves protected identity and registration.

## B — Context and diagnostics

- [x] Add metadata-only bounded journald profiles to existing eventlog handlers.
  Test privacy, invalid rows, denied access, truncation, limits and Windows parity.
- [x] Add logind session enumeration under
  `platform/linux/sessions.py`; use it in `context_profiles/probe.py`.
  Test multiple sessions, domain-qualified names, lock, remote and manager rows.
- [x] Use verified CUPS IPP for printers and queue summary; test missing daemon,
  private fields, queued/printing/error states and bounded output.
- [ ] Run all advertised Linux diagnostic handlers on the real host; only then
  adjust catalog platform support and generated contract artifacts.

## C — Activity and Policy

- [ ] Implement Linux session sensor, X11 and KWin Wayland adapters; validate
  installed KDE APIs before choosing idle/foreground integration.
- [ ] Authenticate Unix IPC using peer PID/UID and OS session; reject forged
  identities, cross-session samples, oversized frames and unexpected messages.
- [ ] Add Linux Policy applicator, state restoration and truthful Sensor Health;
  wire existing ActivityDispatch and WSS ACK gates in runtime/application.py.
- [ ] Package automatic session startup without adding Qt UI to System Core.
- [ ] Verify real domain user, lock/unlock, logout, Wayland and X11.

## D — Browser and audit DLP

- [ ] Share existing browser protocol/extension and content-free projections.
- [ ] Implement Native Messaging forwarding over authenticated local IPC;
  verify installed browser paths, ID/origin validation and frame bounds.
- [ ] Support owned and external browser deployment without modifying GPO files.
- [ ] Implement USB sysfs/udev and CUPS metadata-only audit sources with stable
  event identities; reuse bounded SecurityEventRuntime/SQLite spool and ACKs.
- [ ] Verify browser installation, heartbeat, upload/paste, USB/print source and
  actual receipt; document absent physical resources as unverified.

## E — Reliability

- [ ] Test reconnect, restart, reboot, sensor isolation and cancellation.
- [ ] Test applied update, integrity rejection and crash rollback on the pilot.
- [ ] Exercise bounded queues, disk errors and recovery without identity loss.

## F — Console and publication

- [ ] Verify shared Console device/Context/Policy/Activity/DLP views in Playwright.
- [ ] Update current ALT baseline, install runbook and pc_agent CODEMAP in place.
- [ ] Run one complete relevant release gate plus targeted Windows regressions.
- [ ] Inspect complete diff, clean checks and task-only commits; safely publish
  verified changes to main through the repository process; no production rollout.

## Initial findings / execution ledger

- GitNexus index matches remote main; later requests experienced transport errors.
- Reference host is ALT Workstation K 11.4, KDE/KWin 6.7.4, Python 3.12.13;
  active domain-user X11 session, CUPS/SSSD running, Agent absent, ~13 GiB free.
- Dedicated headless pilot SSH timed out. Reference operator is not in sudoers;
  checking the available root boundary without changing AD or sudo policy.
- Context7 is quota-limited; use upstream documentation and installed API probes.
- Linux Policy/Activity/SecurityEvent composition is absent; eventlog rejects
  Linux; session context uses who; queue summary is Windows-only.
- Legacy pc_agent/AGENTS.md references missing docs and `.agents` skills; use
  existing architecture, source/tests and current CODEMAP rather than invent them.
- Initial Core/RPM: native PyInstaller build passed; rpmbuild initially failed
  because rpm-build-python3 was missing. Declared the build dependency and
  installed that package on the reference test host; RPM build and install
  passed. Baseline package is 3.2.121-alt3, 27,827,405 bytes. No stable release
  or production application deployment has been performed.
- Strict configured-CA HTTPS /healthz returned 200. An audited SSH operator
  call to existing campaign/claim services created a one-use Linux campaign,
  limited to the reference machine's /32 and verified service-user hardware
  fingerprint. Claim passed privately over authenticated SSH/SFTP; no token
  was printed or placed in Git. Dedicated service credential and canonical
  device identity are owned by endpoint-agent, mode 0600. Console confirms
  online Agent/Launcher 3.2.121 and fresh inventory/Context; zero restarts.
- Live source: logind sees active X11, CUPS returns nonempty inventory and zero
  queued jobs; journal projection returns 64 bounded metadata rows. Service
  journal access fails without systemd-journal and succeeds with that group.
  Source tests also exposed the comma-separated loginctl property mistake and
  a journal response bound exceeded by 200 rows; both are fixed and covered.
- Live old RPM inventory returned false for an installed package after entry
  2048; candidate returned true. 3569 packages are within the bounded 8192 scan.
- Checks: local diagnostics/contracts/Windows-session regression subset
  117 passed, 3 skipped; contract-only subset 17 passed; generated contract
  check and compileall passed. ALT Python 3.12 run with RPM tests:
  181 passed, 2 skipped, 2 environment failures (Git is absent in the source
  snapshot); the two git-archive/LF checks separately passed on Windows.
- AD probe: SSSD UID-to-SID and SID-to-name work, but reverse name remains
  unqualified. Activity identity must not rely on that short name alone.
- Pending: claim finalization/restart identity preservation, installed candidate
  adapters, remaining diagnostic smoke, then Activity/IPC and later phases.
- Claim finalization completed only after validating fixed paths, private file
  ownership/modes, canonical identity and credential digest against the durable
  handoff request. Agent restarted without the claim; identity/credential bytes
  remained identical, service running with zero crash restarts.
- Native diagnostics/RPM subset rerun excluding only the two Git-dependent
  snapshot tests: 181 passed, 2 skipped, 2 deselected. Those two LF/archive
  checks passed separately in the real Windows Git checkout. Latest local
  Context/primitives/contracts subset: 115 passed, 3 skipped; generator check
  passed. No full final release gate has yet run.
- C foundation: common local envelope and Activity policy projection extracted
  in 03d98c6ae889f3ee7e13cd74a8d218263b658760; Windows compatibility imports and
  native pipe authorization retained. Targeted Windows/common tests: 34 passed.
- SSSD original UPN is accepted only when its original SID agrees with a
  separate UID-to-SID lookup. Live AD resolution returned a qualified identity;
  neither the principal nor the SID is copied into tracked evidence.
- Linux IPC uses bounded SOCK_SEQPACKET records, SO_PEERCRED, per-record
  SCM_CREDENTIALS and logind session binding. Descriptor passing is rejected
  and received descriptors closed. Inactive/locked OS state overrides a user's
  unlocked sample; finite listener backlog/deadlines and exclusive socket lock.
  Native Linux IPC/identity/sample tests: 29 passed. Runtime integration pending.
- KDE upstream/live API investigation: X11 ScreenSaver idle is milliseconds;
  Wayland KIdleTime polling is unsupported and returns zero. The optional
  user-only Qt/KF6 helper uses idle/resume events on Wayland and reports unknown
  until a real resume establishes its clock. KWin integration reads PID only.
  Native compilation and graphical acceptance are still pending. Build-only
  compiler/Qt development packages are being installed on the reference host;
  apt simulation showed 45 additions, no upgrades/removals.
- IPC foundation final focused Linux run: 20 passed, including mutual client/server
  kernel-credential verification and descriptor-leak rejection. Local Windows
  run: 15 passed, 5 Linux-only skips. KDE helper native build passed with
  -Wall -Wextra -Werror; actual domain-user X11 produced idle/lock/PID facts and
  removed its own KWin script on shutdown. User explicitly authorized ending
  the test graphical session and rebooting for later Wayland/recovery acceptance.
- C source composition uses the existing PolicyRuntime/cache, ActivityDispatch,
  WSS policy ACK gate and SensorHealthRuntime. Linux feature negotiation starts
  at 3.2.122; 3.2.121 remains unsupported. Browser/DLP are not yet advertised on
  Linux. Requests for missing sources fail SENSOR_NOT_READY. A live Linux
  composition regression showed stale listener readiness could ACK after stop;
  application now checks the listener's current availability.
- C targeted Windows/common/architecture/packaging gate: 279 passed, 1 skipped;
  dedicated Linux composition and silent-helper cancellation checks passed.
  User mode branches before enrollment/settings, and receives no credential.
  Optional user-sensor RPM/build integration is in progress, not yet built or
  installed. Agent version remains 3.2.121; no release has been published.
- A concurrent Wayland session initially had no outputs. After ending the
  authorized test X11 session and temporarily
  stopping LightDM, a fresh real Wayland session has one connected, enabled
  output. Native helper produced idle/lock/foreground facts, zero stderr and
  cleaned its own KWin script. A disposable pointer moved by +1/-1 establishes
  a real resume; no keys or contents are captured. Helper now suppresses idle
  and PID when Qt has only a placeholder screen. Domain-user Wayland check
  is starting. Restore LightDM before leaving the reference host unattended.
- Actual domain-user Wayland then passed the same native probe with one
  connected/enabled output, known idle after input, known lock fact,
  foreground PID, zero stderr and script cleanup. Separate identity lookup
  executed as the real endpoint-agent account returned a qualified identity.
  Autostart uses only its own mode-0600 environment file in the user's runtime
  directory, rather than changing global user-manager environment.
- Native KWin sender spoof probe returned AccessDenied/KWIN_REQUIRED and did
  not replace the foreground PID. ALT RPM has def_without/if_with macros but
  lacks upstream bcond_with; corrected the optional package conditional after
  checking the installed RPM macro table. Final two-RPM build remains pending.
- Native ALT spec query confirms the optional build produces exactly the Core
  and user-sensor package definitions. Final focused native composition,
  cancellation, sample and wrapper/spec tests: 15 passed; shell syntax passed.
  The actual domain-user KDE lock reports locked=true; standard root logind
  unlock was then confirmed by the desktop helper reporting locked=false.
- C installed-candidate acceptance uses private Agent 3.2.122. Neither the
  production build registry nor GitHub reserves that Linux version. This is
  a staging candidate, not a stable release or production rollout. Subsequent
  functional runtime changes require another immutable artifact version.
- Existing Endpoint staging uses its own application services and database.
  Strict CA/hostname HTTPS health passed. Preparing the same committed
  Endpoint application there; Helpdesk services/configuration are out of scope.
  Staging migration is 0037; the only pending main migration is existing 0038
  Activity Analytics. Preserve a private database backup before applying it.
- Existing staging upgraded to dfe14d5ed851 after a verified private database
  dump and configuration backup. Migration 0038 passed; strict HTTPS health
  returned 200; Helpdesk PID/start time were identical before and after.
- Native private 3.2.122-alt4 Core (28,319,959 bytes) and optional user-sensor
  (23,041 bytes) RPMs built and installed. RPM upgrade preserved the original
  pilot credential/identity bytes. Production pilot state/config are preserved
  under root-only storage; staging has a separate enrollment and credential.
  One-time staging claim finalized only after canonical identity/hash proof.
  User autostart and hardened user service started successfully as the AD user.
- C live WSS found remaining Windows-only receive guards for Activity and
  Sensor Health despite negotiated Linux Policy. Reproduced with real route
  tests (Linux policy transition cases failed activity_disabled). Receive guards
  now use the same version/platform Policy negotiation as delivery; Browser
  and SecurityEvents remain closed on Linux until phase D implements them.
  Staging pilot temporarily stopped while this server fix is verified/deployed.
- C Gateway fix passed 22 route/delivery tests, including real ASGI WebSocket
  Activity transitions and Sensor Health persistence for Windows and Linux.
- D foundation: extracted the existing Native Messaging stream into shared
  browser_bridge.py and supplied a Linux Unix IPC transport. Windows pipe
  authorization remains platform-owned. Wrong origin/extra arguments reject
  before stdin is read; typed ACK validation and private-error suppression are
  covered. Targeted Linux/common/Windows browser tests: 28 passed. Installation,
  browser policy ownership and live extension handshake remain pending.
- Installed C uncovered a user-unit namespace incompatibility: its mount
  sandbox implicitly maps host root to UID 65534. A native user-unit probe
  reproduced the selector ownership rejection while direct user execution
  succeeded. Preserve the host UID namespace; retain NoNewPrivileges, AF_UNIX,
  SUID/personality restrictions and strict root/service ownership checks.
  Regression failed before the unit fix and passed after it. Focused session,
  listener and packaging tests: 17 passed, 3 platform skips.
- The installed 3.2.122 RPM is unchanged. A root-owned temporary user-unit
  override exercises the corrected namespace until the next RPM packages it;
  remove that acceptance override after upgrading the fixed RPM. The user
  service then ran with zero restarts; real WSS Activity arrived on staging
  with the verified qualified AD identity and honest UNKNOWN before input.
- Full installed Wayland flow now confirmed through staging WSS: Policy
  APPLIED, Sensor Health READY with fresh User Sensor receipt, qualified AD
  identity, ACTIVE after real pointer input (idle=9), LOCKED with no foreground,
  then IDLE after policy threshold 60 seconds (idle=94). Core and user service
  both report zero restarts after correcting the receive/namespace defects.
- D credential-free native entry branches before enrollment/settings, refuses
  root and pins the public packaged extension ID. Core packaging includes only
  that public ID asset. Focused entry/bridge/Windows protocol tests: 34 passed;
  entry/dependency split/browser subset: 33 passed including artifact checks.
  No Linux Browser/DLP capability is advertised by the installed C candidate.
- D USB adapter uses unprivileged kernel netlink group 1, checked sender and
  SCM credentials, bounded content-free fields, boot/sequence event UUIDs and
  the shared Windows/Linux Policy/event projector. Foreign senders, duplicate,
  truncated, oversized and malformed fields reject; synthetic events are ignored.
  Reference service-user subscription succeeded. A real kernel input event
  from the disposable pointer confirmed the sender/credential assumptions;
  this is not claimed as USB hotplug evidence. Native tests: 13 passed; local
  USB/Windows subset: 19 passed, 2 native skips. Physical USB acceptance pending.
- D CUPS source uses explicit safe IPP fields, bounded ID pagination and a
  startup baseline; old history is skipped without requesting document names.
  Stable CUPS UUID/time facts and frozen pending records preserve identity on
  spool retries. Shared print projection retains Windows notification behavior.
  Local print/Windows/CUPS tests: 27 passed. Service-user live CUPS query returned
  the held fixture's ID/UUID/printer URI/state/time/copies; pages were absent and
  remain unknown. A separate native source probe observed a newly submitted
  held fixture and persisted one PRINT_JOB through the existing SQLite spool
  with no source failures, titles or contents. This is source/spool evidence,
  not installed Gateway delivery. Disposable queue and its two jobs are removed;
  no pre-existing printer definition was changed. The earlier inventory of 16
  was a bounded projection, not a verified total; lpstat currently lists 47
  destinations. Installed staging DLP acceptance is still pending.
- D root-policy boundary: the existing Windows request/reply protocol is now
  shared without changing service-SID authentication. Linux accepts only apply
  and relinquish for fixed browser families from the actual Core UID, checking
  both connection and record credentials. Policy files use trusted root paths,
  durable ownership intent and rename-no-replace publication. Existing GPO,
  unknown files, modified owned files and late corporate conflicts are preserved.
  Native ALT root fixture/protocol/IPC checks: 27 passed. Local Windows/helper
  regressions: 32 passed, 4 native skips. RPM service/client wiring and installed
  Browser Sensor acceptance remain pending; no new capability is advertised.
- D optional RPM now stages the credential-free native wrapper, pinned
  Chromium/Chrome manifests and an isolated stdlib root Policy helper. The
  helper has fixed write paths, a service-group-only socket and no command/path
  inputs. Preparation preserves existing directories and creates only missing
  root paths with public metadata permissions even under a private umask.
  Linux Policy uses fixed operations and reports conflicts/helper failures;
  Activity-only installations without browser ownership do not need the helper.
  Browser status projection/ACK gating is shared with Windows. Native paths for
  Yandex remain unverified because the browser is absent. Native ALT root IPC,
  ownership, browser facts, wrapper and RPM macro checks: 31 passed. Local
  targeted/common/Windows/packaging checks: 52 passed, 3 native skips. An initial
  native packaging assertion used a stale selectively copied user unit; copying
  the committed fixed unit resolved it. Next candidate must use a full exact
  source archive; installed browser/WSS tests are still pending.
- D runtime composition now routes Linux USB, CUPS and browser IPC through the
  existing SecurityEventRuntime and protected SQLite spool. Windows/Linux share
  the bounded durable callback. A failed optional USB source does not prevent
  Print from persisting; requesting failed USB audit returns SENSOR_NOT_READY.
  Browser availability is rechecked from trusted installed native-host files at
  policy application. Core >=3.2.123 negotiates Browser/DLP separately from the
  3.2.122 Activity-only candidate. Gateway receive guards use that same boundary.
  Real ASGI tests first reproduced the Windows-only Browser/DLP rejection, then
  passed persistence, ACK and idempotent replay for both platforms. Targeted
  runtime/Windows/Gateway/policy checks: 77 passed, 1 native skip. GitNexus route
  lookup/symbol lookup did not resolve this dynamic handler; file impact found
  the direct main.py import (LOW). Source and route tests verify the actual
  dynamic boundary. Installed candidate/version bump and D live tests pending.
- D failure-path regression found Browser Status reopening after a rejected
  Policy ACK. The server correctly rejects such reports, which would otherwise
  interrupt WSS precisely when an optional source fails. Replacement delivery
  now pauses all policy-gated streams; Browser Status resumes only after an
  APPLIED ACK, while Sensor Health can report the rejected policy. Regression
  reproduced the missing pause before the fix. Runtime/common/Windows/security
  checks: 65 passed, 1 native skip.
- D/E spool fault injection reproduced two Core-sensitive paths: initial spool
  open failure aborted startup, and a transient read failure stopped its WSS
  sender. Startup now continues with honest unavailable health/source gating;
  the common sender retries bounded reads/initial opening without resetting or
  deleting data. A failed durable ACK retains the batch for replay. Policy
  readiness reads actual spool health rather than a stale startup flag.
  Security/runtime/Windows/health checks: 72 passed, 1 native skip.
- E configuration-loop RCA: the observed invalid_service_origin returned 75;
  launcher treated it as a startup crash and could request rollback. ALT setup
  refusals now return the unit's non-restarting 78, which launcher propagates
  immediately without retry/rollback. Terminal enrollment denied/invalid
  credentials also use 78; transient transport/persistence failures retain 75.
  The new configuration tests failed before the fix. Native ALT launcher,
  updater, enrollment and runtime checks: 112 passed, 3 Windows skips. Local
  runtime/new launcher checks after terminal-status coverage: 64 passed.
  A broad Windows invocation of Linux filesystem update tests failed on absent
  os.fchmod (34 failures, 76 passes, 5 skips); those native filesystem checks
  were rerun on ALT and passed rather than emulating Linux ownership on Windows.
- Next private D candidate is 3.2.123-alt4. Read-only production UpdateBuild
  lookup found no reserved 3.2.122/123/124 on any platform/channel; GitHub releases
  were empty. Previously installed 3.2.122 runtime bytes are preserved. The new
  candidate will be built from one exact committed full source archive and is
  not authorized for production rollout or stable-channel publication yet.
