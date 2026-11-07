# Test120: automatic full Setup158 acceptance

Status: **APPLIED**. Endpoint assigned and delivered full signed Setup158-r3 to
192.168.101.120. Actual native exit0 was followed by native/Core provenance,
private-file, ordinary-session, service,183-second runtime and independent WSS
checks. Endpoint accepted the final report on2026-11-03 at13:05:11.530911 UTC.
Fresh follow-up on2026-11-04 again confirmed158 and a successful health command.

## Scope and authorization

- Exact device: `0051645c-0e81-4c21-bf52-befcd5ef5407`, host `DESKTOP-9ST5HO2`.
- The source profile was an **existing Foundation158 with ZIP Core157**. Full Setup
  reconciled it into MSI-owned Core158/Foundation158. This is not a fresh native
  Foundation156в†’158 qualification or a fleet rollout.
- User approved a one-time domain SMB/TaskScheduler preparation because the old158
  stager failed before downloading its own fix. Only the canonical updates
  directory owner changed SYSTEMв†’LocalService on2026-11-03 at10:03:01 UTC. Original
  group/DACL and all four private files were preserved, and the temporary task was
  deleted. This initial migration is therefore not zero-preparation.
- All subsequent Core bootstrap/return, recovery and full Setup delivery ran through
  Endpoint. No workstation SSH or manual Setup launch was used. Administrative
  assignments used canonical audited server services from authorized production
  maintenance, actor `ssh-osn-admin`; a real Console button click is not claimed.
- Primary published agent156, public enrollment permissions/defaults, unrelated AD/GPO
  state and Linux publication remain unchanged. Existing158 qualification is retained
  in the separate versioned release record. Core162 is only a Windows bridge.

## Accepted installation

| Evidence | Actual result |
| --- | --- |
| Setup release | `b06ce3dd-49ea-4202-aa55-d446e0dacc6b` |
| Assignment | `f032a785-deaa-4034-892e-8402f4a3547f` |
| Attempt | `5e59c43a-96be-4830-9e33-d1eb4568ab2d` |
| Assigned |2026-11-03T12:59:51.489683Z |
| Artifact GET from test120 |13:00:29Z,HTTP200,145929792 bytes |
| Native start |13:00:43.989427Z |
| Native end |13:01:39.4912496Z,exit0 |
| Local result |`UPDATED / SERVICE_RUNNING`,13:01:38.987434Z |
| Server acceptance |13:05:11.530911Z,`applied / setup_post_restart_confirmed` |
| Foundation/Core |`3.2.158 / 3.2.158`,Core origin MSI |
| Native/runtime source |`9423d9c27ea6b2d6c544c1bcdc1edb7cc9d15421` |
| Runtime observation |183.191 seconds,6 samples,1 user sensor |
| Sensor CPU maximum |0.0064% of total logical-CPU capacity over sampled intervals |
| Services/companions/connection |Stable; captured surviving ordinary-user companions restored |
| Private files |Credential,identity,origin and CA bytes/file IDs/owner/group/DACL preserved |
| Pending native/Core transaction |False |

The server independently required a new post-start authenticated WSS with target
versions. Later API deployment caused a normal subsequent reconnect; the terminal
installation receipt is unchanged. Native success alone did not mark the job applied.
CPU values qualify these observations only, not every workload or long-term performance.

Full immutable artifact/source/signature bindings are in
`docs/releases/windows-3.2.158-r3-setup.json`. The original MSI SHA-256 is
`b7d3ccebdeb5db1bc0b10af14923244c96b1debb3d1ff78cb4e8c062fe56d1a1`.
R3 EXE SHA-256 is `3a603f2440bf501b85032e0defcdb8123efb5bdb31c1a7d4ed87433fcf7f7bb2`.
Its wrapper source is `5cb267d3440511a62e466f49e6cc4ce80c3897a8`;
MSI and original ZIP bytes remain frozen at native source9423.

## Failures and genuine recovery retained

1. Core159 applied10:04:07Z, but observer1.0.0 failed mutex SID translation before
   HTTP/native start. Preparation `56d7d76b-a925-4c61-9e76-116d8f2137ac` was cancelled
   before further stages; actual Core history remains intact.
2. Core160 verifier failed10:19:41Z on Windows PowerShell5.1 null backup-path binding.
   Selector stayed159; preparation `49d12c58-075e-4651-b807-bc527249945a` is blocked.
3. Core161/client1.0.3 applied11:04:03Z; canonical return157 applied11:09:08Z.
   Original frozen Setup158 assignment `cc4b2c66-bab0-4ab5-80d6-25f7f8263785` blocked
   before native start: its preflight incorrectly called equal Foundation158 current
   while selected Core was157. No native acceptance was fabricated.
4. R2 assignment `aff35213-1bcc-4784-ade0-c8b9dbf4072c` really launched and exited21
   at11:59:50Z. Its rebuilt Core ZIP had identical122 uncompressed entries but four
   changed ZIP timestamps, so its bytes conflicted with the immutable existing cache.
   No new bridge/native journal was created. R3 reuses the original fully verified
   archive instead of deleting or replacing that cache.
5. Recovery preparation `7d33f207-8080-41f4-a66f-f6f2ff062746` kept the original native
   hold committed while canonical Core162 rollout `72699ad3-7707-45ac-a225-f598138613c7`
   applied12:49:17Z and installed signed observer1.0.4. Canonical return157
   `86b3d9f5-7943-4258-8390-5813a1c8411a` applied12:54:22Z.
6. Observer1.0.4 proved exact unchanged source ZIP/MSI/revisions, original terminal
   native journal, no pending transaction, private continuity, restored ordinary
   companions and183.327 seconds stable observation. Server also verified qualified
   presence, completed/applied return and live matching WSS. R2 honestly settled
   **failed**, exit21 unchanged, at12:57:47.237991Z. It was not called a rollback or
   success. Only after this acceptance was R3 assigned.

Unknown exits, missing process outcomes or unsettled journals continue to retain
exclusive recovery ownership. Native actions are not replayed after lost responses.

## Post-install and next-day checks

- Health collection `18401f05-ea6f-4334-8694-288ec307f5d0` completed
  2026-11-03T13:05:37.743238Z,command status `succeeded`,warnings `[]`.
- Fresh health collection `4954dec4-0f71-4677-97e5-2daee2090e61` completed
  2026-11-04T09:22:24.075668Z,command status `succeeded`,warnings `[]`.
  Resources:load_1m0,free5217259520 bytes,uptime186704 seconds. The health profile's
  service list is empty; service state was checked separately through Windows SCM.
- 2026-11-04:Core/Foundation158 and qualified observer1.0.4 are fresh and ready;
  authenticated source120 WSS is connected. SCM:EndpointAgent and BrowserPolicy
  RUNNING;Updater STOPPED with DEMAND_START/LocalSystem,exit0,as intended while idle.
- Independent read-only SMB native-file evidence again matches the pre-preparation
  baseline for all four private files, including bytes/file IDs/security.
- No active Core target or full Setup assignment remains for test120. Failed and
  blocked historical receipts remain immutable. Disposable PostgreSQL test roles0.
- Production `/opt/endpoint-platform/current` points to
  `endpoint-platform-4fa766c94326`;API/worker active,strict hostname/CA HTTPS health
  reports database OK,schema0044. Actual SSO/WorkTime baseline62fb4 was preserved;
  server dependencies were pinned to the original production freeze.

## Automated and browser verification

- Installer/reused-media gate:167 passed. Includes actual Windows PowerShell MSI
  signature admission and frozen archive validation; substituted source/tree refused.
- Final focused server/Core/contracts/client regression:140 passed. This includes
  unknown-outcome ownership, qualified executors, cancellation/auth revocation,
  source recovery, ZIP hash comparison, recovery ACK ordering and source-version soak.
- Real disposable PostgreSQL migration/locks/cookie+CSRF/scope/unique recovery hold:
  4 passed. Earlier migration/Core persistence baseline:10 passed. Test roles/databases
  cleaned; no test database is used by production.
- Existing Windows runtime/recovery/initial-payload regression:125 passed.
- UI:70 passed;TypeScript/Vite production build passed. The build reports a nonfatal
  bundle-size advisory; dependencies were not upgraded.
- Playwright MCP:localhost disposable Console fixture at1440/390px; same-version
  R2/R3 artifacts are distinguishable,selection works,no horizontal overflow or
  page errors. Recovery ownership disables another assignment and offers no cancel.
  Only this local fixture used a self-signed browser context; production TLS was
  never bypassed. This is UI contract testing,not live administrative UI acceptance.

Exact final focused command:

```powershell
py -m pytest -q tests/server/test_setup_recovery.py tests/server/test_setup_update_service.py tests/server/test_setup_preparation.py tests/server/test_setup_update_api.py tests/contracts/test_setup_updates.py tests/packaging/test_setup_failed_source_recovery.py tests/packaging/test_setup_client_journal.py tests/packaging/test_setup_client_admission.py pc_agent/tests/windows/test_setup_update_bootstrap.py tests/server/test_update_service.py tests/server/test_update_agent_api.py -W ignore --tb=short
```

Other gates: `py $env:TEMP/endpoint-setup-pg-run.py`, `npm test`, `npm run build`,
`git diff --check`;installer gate covers `test_setup_core_archive_reuse.py`,
`test_setup_reused_msi_signature.py`,`test_windows_setup_contract.py`,
`test_setup_entry.py`,`test_fleet_preflight.py`,`test_setup_selected_core_reconciliation.py`.
Native journal tests deliberately replace HTTP/native boundaries; real test120
acceptance above is separate evidence. Temporary localhost QA server/context are
no longer present; original user checkouts and browser sessions were preserved.

## Commits and included files

| Commit | Message | Included files/areas | Verification |
| --- | --- | --- | --- |
|`5cb267d3440511a62e466f49e6cc4ce80c3897a8`|`fix(packaging): reuse the verified frozen Setup Core archive`|`packaging/windows/build-setup.ps1`,`tools/release/verify_setup_core_archive.py`,`tests/packaging/test_setup_core_archive_reuse.py`|167 installer tests;actual frozen MSI/ZIP comparison;R3 signed build |
|`2c226e6208e28600a52152cadf2f0ec649eaa428`|`fix(packaging): reuse the verified frozen Setup Core archive`|Exact cherry-pick of those three packaging files into production feature branch|Identical committed change;source preserved |
|`b9976195cf68be57da7dd860fa062fba6b533b8d`|`fix(updates): recover the Setup observer without releasing native ownership`|`endpoint_contracts/setup_updates.py`,`endpoint_server/setup_updates/{preparation,service}.py`,`packaging/windows/EndpointSetupUpdater.ps1`,`pc_agent/version.py`,plan and six recovery/preparation/API/PostgreSQL/service/Windows test files|140 focused tests,PG4,qualified signed Core162 build and actual recovery |
|`4fa766c94326a68999d37975807e355c3159bb83`|`fix(console): distinguish full Setup artifact revisions`|`webapp/src/FullSetupPage.tsx`,`webapp/src/FullSetupPage.test.tsx`|70 UI tests,typecheck/build,Playwright1440/390,deployed production |

The feature branch is `codex/full-setup-autoupdate-production`;the frozen158 build
branch is `codex/setup158-r2-core-selection`. Commits are local;no force push or
published-history rewrite was performed. Build-only checkout remains clean for
reproducing the signed158 wrapper;the original dirty user checkout was not touched.

## Limits

- One approved legacy directory-owner preparation was required; do not claim a
  zero-preparation initial158 migration or broaden this exception to other hosts.
- R3 success qualifies the actual Foundation158/ZIP157 source only. Earlier separate
  native156в†’158/fleet evidence must not be represented as this automatic test.
- Native failures outside known exit21/unchanged-source recovery remain held.
- Deferred minor:Core UpdateConflict during Setup preparation rolls back safely but
  currently maps to generic HTTP500 rather than409. No false success results.
- Ordinary-user companion restore was verified in the captured surviving session;
  broader fleet/session profiles and unrelated WorkTime/SSO acceptance were not tested.

Operator evidence contains private **metadata only** outside Git:
`C:\Users\admin-2\AppData\Local\Codex\endpoint-fullsetup-automatic-20261103`.
Credential contents,private keys,environment files and CA deployment inputs are
not included in the repository or this report.
