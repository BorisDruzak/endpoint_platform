# Windows Setup owner-transfer correction: candidate 3.2.150

## Change and source identity

The original elevated 3.2.149 Setup failed in reconciliation while copying the
SYSTEM owner and DACL from current.json to its atomic replacement: Windows 1307.
Its subsequent diagnostic append populated Agent/install.log and blocked the
authenticated empty-root recovery expectation with PROVENANCE_CONFLICT.

Correction commit: `1660e930c284eccd10afc91b106c46ec089aad6a`
(`fix(installer): preserve SYSTEM ownership during elevated setup`). Files include
acl.py, setup_entry.py, native token/NTFS regressions, Setup tests, version/golden
fixtures, CODEMAP, runbook, packaging README and the design/plan.

Runtime binding commit: `793f2611a98db928cef5f3fc5580df65479e69af`
(`build(agent): bind Windows 3.2.150 to verified runtime bytes`), containing only
packaging/windows/initial-runtime-3.2.150.json.

The effective thread token, or process token only when no thread token exists,
temporarily enables an already-held SeRestorePrivilege around owner assignment.
Prior attributes are restored on success/failure. Missing privileges retain normal
Windows checks. Setup diagnostics now live in the protected Installer directory.
Append requires successful directory protection and validates/pins a regular,
single-link, trusted-owner file before writing through its native handle.

There are no Gateway protocol, HTTP contract, server deployment or database schema
changes. GitNexus upstream analysis identified 17 related symbols (medium impact),
including reconciliation, selector migration and the offline updater; source/tests
verified those dynamic callers.

## Source and artifact verification

Python 3.12.14 commands executed from the isolated correction checkout:

- `python -m pytest pc_agent/tests/windows tests/packaging tests/canary tests/tools -q -o faulthandler_timeout=120`: **3199 passed, 163 skipped**, 402.33 seconds.
- Native ownership/Setup/context regressions: **79 passed**. Initial regressions
  demonstrated disabled-privilege and fresh-root log failures before correction.
  Three additional rejected-directory/junction/hardlink regressions were RED, then
  GREEN after the append boundary was tightened. Independent reviewer: **75 passed**,
  no remaining Important findings.
- `python -m pytest tests/packaging/test_initial_runtime_contract.py tests/packaging/test_windows_setup_contract.py -q`: **36 passed**.
- `python tools/contracts/generate_contract_artifacts.py --check`,
  `python -m compileall -q pc_agent/platform/windows endpoint_contracts`, and
  `git diff --check`: passed.
- An initial bare `python -m pytest -q -o faulthandler_timeout=120` on Windows
  reported 5338 passed, 359 skipped and 43 failures. Two version-golden failures
  were corrected and passed the complete Windows gate above. The other 41 are
  ALT/POSIX and Unix file-permission cases executed on Windows (including absent
  os.fchmod); the complete cross-platform suite is not claimed green.

Canonical Core, MSI and Setup build scripts were used, with the retained pinned
Python/WiX toolchain, exact source epoch, deployment CA and organizational signer.
All 211 manifest source bindings and 11 frozen entrypoint source closures were
verified against this checkout. Frozen installer-host ACL bytecode and frozen
Setup entrypoint bytecode exactly match reviewed source. Both MSI and EXE have
Valid organizational Authenticode signatures with timestamps.

| Artifact | SHA-256 |
| --- | --- |
| EndpointAgentSetup-3.2.150-x64.exe | b873c0db6c1973f54060bc0ef87a8a5010e21927c4828c8c0d8c3989e4f59eab |
| EndpointAgent-3.2.150-x64.msi | 00015570fe92fc0935ba9f6a34de2eee0601488035de996f6594a624df31811f |

## Original-machine observations

Evidence and operator receipts are retained outside Git. Original logs/results
were preserved before intervention; all four private enrollment files were absent.
The exact original 149 package recovered its interrupted install with exit 0 and
retired the fence normally. A signed native scratch probe built from corrected
source passed on the same workstation: elevated token, restore enabled bit clear
before and after, exact SYSTEM owner/DACL, unchanged payloads, scratch removed.

The original 149 full Setup then reached server review: AMBIGUOUS_CAMPAIGN, because
the ordinary subnet AUTO campaign overlaps the departmental pilot. Its waiting
Setup processes were stopped only after native work/fence completion.

For a fresh 150 test, canonical 149 uninstall exposed a separate existing
msi-enter defect: full feature-state inspection during transient native product
unpublication. Its exact authenticated RecoverInterruptedInstall path completed
the captured uninstall with exit 0; no manual fence or ownership deletion was
used. The correction does not modify that separate ordinary-uninstall callback.

The actual signed 150 EXE was launched with the parent's restore privilege
explicitly disabled. Native install/reconciliation completed and retired its
fence. MSI reports installed state 5/version 3.2.150; current.json and protected
foundation authority bind the same 150 source/package. Setup then returned
**30 / ENROLLMENT / NO_MATCHING_CAMPAIGN**, rather than an MSI failure.

The same signed EXE was run a second time, again with the parent's restore
privilege disabled. It passed native maintenance/reconciliation and returned
the same enrollment-only denial. Final postflight at 12:56:42 UTC confirmed
product state 5; Foundation and initial-runtime features both LOCAL (3); matching
150 selector/foundation/package; SYSTEM selector owner; no active fence; and
zero native installer failure events since the first 150 test. Both attempts
returned code 30 solely at ENROLLMENT/NO_MATCHING_CAMPAIGN.

Before campaign authorization, EndpointAgent was Automatic/stopped without
enrollment credentials; Updater was Manual/stopped and Browser Policy was
Automatic/running. No operational connection was claimed at that checkpoint.
All four private files were still absent. The old 149 Agent/install.log was retained; 150
appended its new diagnostic flow only to Installer/install.log.

## Completed enrollment after explicit user authorization

The user subsequently approved a temporary campaign for this workstation only.
Canonical campaign issuance plus an immutable audit event created one AUTO
campaign for `192.168.101.29/32`, release `3.2.150` only, max uses 1, expiry
2026-10-27 14:08:45 UTC (19:08:45 Asia/Yekaterinburg). Existing campaigns were not
modified; the raw campaign bearer was neither returned to the operator nor saved.

The identical signed Setup was run again with the parent's restore privilege
disabled. At 2026-10-26 14:10:17 UTC it returned **0 / COMPLETED / SERVICE_RUNNING**.
The server independently confirmed the request completed under the new campaign,
one device credential, and one consumed use out of one. Core and launcher both
report 3.2.150. The agent opened WSS from the authorized address; its same session
remained open and heartbeat advanced from 14:10:43 to 14:12:13 UTC. At 14:12:37 UTC
the observed heartbeat age was 24.243 seconds. This is a short acceptance check,
not a long-duration soak.

A final normal Setup rerun returned **10 / ALREADY_INSTALLED / SERVICE_RUNNING**
at 14:11:50 UTC. It was checked with before/after private-file hashes and
ACLs held only in memory. All four private files and descriptors remained
unchanged; Agent service PID 3928 and Core PID 4932 also remained unchanged.
The final rerun result and postflight are retained in the private operator receipt.
Final local postflight confirms Agent Automatic/running, Browser Policy
Automatic/running, Updater Manual/stopped, all four protected enrollment files,
the exact 150 selector, and no active native fence. Independent final server
verification confirms the same open WSS session with a 20.750-second heartbeat
age and exactly one active device credential.

The temporary campaign is exhausted (1/1) and cannot authorize another enrollment.
Its original expiry remains unchanged. This candidate has not been published as
the fleet default, pushed to main, or assigned through GPO. The separate ordinary
uninstall callback limitation described above remains outside this correction.
