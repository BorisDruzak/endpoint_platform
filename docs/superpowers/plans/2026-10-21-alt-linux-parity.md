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
