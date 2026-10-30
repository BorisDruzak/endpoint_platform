# Automatic156 enrollment and visible Windows Setup

The B2-zhkh-s5 request used 156 and selected `test`/MANUAL. Older AUTO campaigns
did not permit 156. The client then polled silently for 30 minutes and lost its
approval-wait reason on timeout. The old request expired 2026-10-28 at 09:18 UTC;
it cannot be completed by changing current campaign settings.

## Configuration applied

Campaign 09e62472-a6ae-49ab-aaaa-6613836b4423 changed from MANUAL to AUTO. Network
192.168.101.0/24, quota 100, expiry 2030-09-27 and other campaigns were preserved.
The distinct signed Setup revision was subsequently added to that same campaign.
The deployed canonical selector checked both release IDs across all 254 usable
addresses: 508 uniquely AUTO-approved selections, no overlap for these releases.
Immutable audit request IDs are `operator-auto156-20261031` and
`operator-setup156-progress-20261031`. No service restart, server deployment,
schema migration, GPO change or fleet rollout was performed.

## Delivered artifact

- Setup: `EndpointAgentSetup-3.2.156+setup.1-x64.exe`, 145912568 bytes.
- SHA256: `c98851e539004384d5b216d075b7b16a33888990840c8f218514dcb843590cbf`.
- Setup source commit: `b115712c43e8ca7ae46418489edc24ab61d82e3a`,
  `fix(installer): show progress and explain enrollment waits`.
- Payload/agent version: 3.2.156; exact retained signed MSI SHA256
  `ab6cde32554798a18b446c8e33ce6f0926eba6a85439bc7224a08a88b25a1073`.
- Retained MSI source: `6ed41cd01d494e46111a452c2ae3a844f723175b`.
- Organizational Authenticode signature and DigiCert timestamp: Valid.
- Release registry ID: `26fa3bb2-f9f5-424f-a885-2ce6cb489d15`.
- Operator directory:`C:\endpoint-platform-wix-build\setup-progress-3.2.156-r1-b115712\releases`.
- Local delivery:`C:\Users\admin-2\Downloads\EndpointAgentSetup-3.2.156+setup.1-x64.exe`.
- Published download:`https://endpoint.sosnadmin.local/api/admin/console/installer/releases/26fa3bb2-f9f5-424f-a885-2ce6cb489d15/download`.

Windows 158 and old 156 EXE hashes were independently re-read on the production
host and remain unchanged. The new registry entry is the latest public Setup;
main qualified runtime 158 and the Linux kit were not replaced.

## Implementation and verification

The window shows current stage, indeterminate progress, elapsed time, bounded
Russian explanations and a final result. Native work stays on the calling
thread. Window Close is disabled while work runs and enabled at completion.
Quiet/preflight/recovery remain headless. Approval timeout retains its reason;
initial-context waits are distinguished from connection waits, and companion
startup warnings do not masquerade as failed service installation.

- `python -m pytest pc_agent/tests/windows tests/packaging -q -o faulthandler_timeout=120`
  under Python 3.12.14: 2482 passed, 5 skipped,358.47 seconds.
- After review corrections, focused progress/UI/Setup/packaging suite:114 passed.
  Reviewer's independent focused verification:37 passed; no remaining Critical
  or Important findings.
- Ruff on new progress/UI/tests and changed enrollment module, compileall and
  `git diff --check`:passed. Historical `scripts/verify_workspace.py` is absent
  in this repository; the unrelated Helpdesk workspace was not used.
- Canonical PowerShell/PyInstaller build and privileged-bootstrap scan passed.
  Frozen Setup entry and all three changed modules exactly match reviewed source
  bytecode under Python3.12; embedded config, MSI and common-controls/UAC manifest
  were independently checked.
- Pinned domain VM123/DESKTOP-2EVR855: signed preflight 0, existing-device rerun 10,
  native 158 retained, all four private-file hashes/ACLs/timestamps preserved,
  EndpointAgent stayed running with the same PID.
- Domain ADMIN-2: signed preflight 0 and interactive existing-device result 10.
  Accessibility tree contains the success explanation, result code and enabled
  Close button. Three existing private files were preserved; endpoint-origin
  remained legitimately absent. Service PID 42032 was unchanged.
- Native window smoke verified creation, close veto during work, terminal close
  and UI-thread completion. Screenshot capture returned black and input tools
  returned access denied despite an Active RDP session; pixel-level visual
  acceptance is not claimed.

This is a signed installer/UI and existing-device qualification, not a fresh
native enrollment qualification. B2 was unreachable on ICMP, SSH, SMB, RPC,
WinRM and RDP during checks. Its actual fresh retry still requires the PC to be
available and a new Setup run. Existing expired requests were not rewritten.

Code files included in the source commit: packaging/windows/build-setup.ps1,
pc_agent/setup_progress.py,pc_agent/windows_setup.py,
pc_agent/platform/windows/setup_entry.py,
pc_agent/platform/windows/setup_progress_ui.py,
pc_agent/pyinstaller_windows_setup.spec,pc_agent/windows_setup.manifest;
corresponding progress/UI/Setup/packaging tests, CODEMAP, packaging README,
design and implementation plan. Gateway, HTTP contracts and running Core bytes
were not changed.

Operator evidence and safe controller scripts are retained at
`C:\endpoint-platform-wix-build\installer-domain-audit-20261031`.
