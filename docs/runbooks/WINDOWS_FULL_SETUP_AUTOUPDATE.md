# Windows full Setup updates through Endpoint

Use Console **Релизы и обновления → Полный Setup** for an enrolled Windows
device. Select the exact EXE filename as well as its version, select the device,
enter a reason and assign. Revisions of the same158 native package have distinct
immutable EXE names. The public enrollment campaign/default installer is separate.

Endpoint stores and audits the assignment. A qualified signed SYSTEM client
downloads only from the enrolled HTTPS origin using its existing device identity,
validates size/hash/publisher/timestamp and native preflight, then runs the full
Setup with `--quiet`. No SSH or interactive action on the workstation is part of
this delivery. Existing Core-only clients continue to receive ZIP archives only.

## Final uninstall and Observer cleanup

In a Setup build that supports cleanup result 69, ordinary final product removal
also retires the owned `EndpointSetupUpdater` task. The installer records native
MSI success and the removal event before retiring the task. Setup 69 means the
product was removed and Observer cleanup needs attention. The warning includes
the removal transaction UUID. The protected transaction archive also contains
`completed.json` and `observer-cleanup.json` with that UUID and package hash.
If Support also needs cleanup, the wrapper returns 68 and records each component
separately. Check delivery of the removal independently of Observer cleanup.
On a registered Windows 10 guest with .268 and a live Gateway, the same
device received ACK 5 for the original removal before reboot. MSI returned 0
and the Observer task stayed absent after reboot. The test harness lost the
outer wrapper exit code. [Online removal receipt](C:/endpoint-platform-wix-build/stab15-win268-online-uninstall/online-final-removal.md)

On a registered Windows 10 guest with .268, removal while offline retained the
original event. After reboot and network return there was no delivery task and
the server still had the previous installation. The next signed Setup delivered
the original removal before its own install event, on the same device and
generation. [Exact .268 results](../releases/windows-3.2.268-candidate.json)

On Windows 10 with .275, an offline removal followed by an ordinary reboot
and an offline reinstall left both installation events pending. After network
return, verify the original removal ID and then the reinstall ID on the same
device. In the test both acknowledgements arrived during the second scheduled
Support reinstall attempt. Core passed its health check. The Support service
was still unavailable and its task remained registered at the last observation.
[.275 removal and reinstall evidence](../releases/windows-3.2.275-candidate.json)

After resolving the reported conflict, run the wrapper from the same verified
release in an elevated Windows PowerShell session. Supply its matching MSI and
manifest and the UUID from the original removal.

```powershell
& $wrapper -Operation RetryObserverCleanup -CleanupTransactionId $transactionId `
    -MsiPath $msi -ReleaseManifest $manifest
$LASTEXITCODE
```

On signed .268, this retry reports only the Observer outcome. After an initial
68, a retry can return 0 when Observer is gone even if Support still needs
attention. Check the Support service and its helper before closing that case.
The corrected wrapper rechecks Support and returns 68 while its removal remains
incomplete, 69 when only Observer remains, and 0 when both checks pass.
The retry acts only on Observer. The original MSI outcome, lifecycle event and
Support receipt stay in their protected records. An active installation or a
newer product takes precedence. [Verified .268 outcomes](../releases/windows-3.2.268-candidate.json)

On signed .271, a cleanup-only retry after 69 returned 0 once Observer
could be removed. With both components remaining, the sequence was
68 → 68 → 0 as Observer and then the Support residue were cleared. In both
Windows 10 trials the retries started no MSI process. The Support trial
used a leftover signed helper file. [Exact .271 receipts](../releases/windows-3.2.271-candidate.json)

If the same product was reinstalled after exit 69, use the latest installation
record. On Windows 10 with signed .268, retrying the old removal UUID returned
wrapper exit 1 with `OWNER_AUTH_FAILED`. Application event 1001 from
`Endpoint Platform Installer` recorded `PROVENANCE_CONFLICT`. The newer
installation owned the enabled Observer task. Its XML and the installed MSI
registration matched their values before the retry.
[Signed .268 reinstall and stale retry](C:/endpoint-platform-wix-build/stab15-win268-stale-observer/qualification.json)

### Interpreting exit 10 on a local .271 rerun

Read the Setup result status alongside the exit code. On registered Windows
10 build 19045, the same signed Setup returned 10 in both cases below.

| Starting state | Setup status | Observed outcome |
| --- | --- | --- |
| Healthy .271 already running | `ALREADY_INSTALLED` | MSI did not run. The server kept its existing installation event and acknowledgement. |
| .271 removed offline with device identity retained, then reinstalled online | `REPAIRED` | MSI installed .271 with exit 0. During Setup the server accepted the original removal, followed by the new installation on the same card. |

After offline removal, restoring connectivity alone left the server showing
the previous installation throughout the observation window. To verify a
subsequent reinstall, check the order of the removal and installation on the
device card and confirm a fresh Core connection. [Windows 10 qualification](../verification/2026-11-14-agent-release-qualification-matrix.md)

## Pending command results during rollback

Full Setup rolls back an unconfirmed trial within its original upgrade
transaction. Once Windows .271 is accepted, Full Setup has no supported
in-place downgrade to .264. The .271 Observer rejects a target older than
the installed Foundation or Core. On a healthy .271, running the older
signed .264 Setup locally can return `10 / ALREADY_INSTALLED` while .271
stays installed. Check the installed version before recording a rollback.
[Windows qualification matrix](../verification/2026-11-14-agent-release-qualification-matrix.md)

When a trial returns to its previous version, check for unacknowledged
command results and preserve the local journal. In the separate journal
test with .268 and .205 runtime modules, the .205 handler left the .268
result queued. After .268 resumed, the matching acknowledgement cleared it.
Submitting a new command creates a separate operation.
[Signed Windows runtime check](../verification/2026-11-19-stab02-windows-192-263-journal.md)

## Full Setup delivery client

The current delivery client is1.0.5. When preparation is required, server
`setup_updates.preparation.request_setup` creates canonical Core163 bootstrap
and exact Core157 return operations before the full Setup assignment. A genuine
Foundation156 instead returns to the retained compatible Core155: Core157 requires
Foundation157 and must never have its minimum weakened. The selected immutable
return build is persisted before bootstrap. The Core
verifier installs the signed observer locally; its task and journal live outside
the MSI-owned Agent directory and survive full Setup. Readiness is not success.

Applied requires real Setup exit0, verified target Foundation/Core/source/MSI,
preserved credential/identity/origin/CA bytes, file IDs and owner/group/DACL,
restored surviving ordinary-user companions,180 seconds of runtime observation
and an independently verified fresh post-install WSS. The client reports the
sensor CPU measurements. No user password or administrator user session is needed.

## Core failures from Windows candidate 3.2.250

After an unexpected Core exit, look for the matching event in the Windows
Application log on the affected device. The insertion string records the
runtime stage, exception type, module, function and source line. Use the
source revision of the installed Core when looking up that line.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    ProviderName = 'EndpointAgent'
    Id = 255
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object { $_.Properties[0].Value -like 'EndpointAgent Core runtime failure:*' } |
    Select-Object TimeCreated, RecordId, @{Name='Diagnostic'; Expression={$_.Properties[0].Value}}
```

The diagnostic carries no exception message, traceback text, credentials
or command payload. Event Log write failures preserve the original Core
exit status. Windows 3.2.245 records its historical launcher exit event.

## Recovery

Cancellation stops only stages that have not started. After native start,
uncertain outcomes retain exclusive `recovery_required` ownership. Never clear
that hold, delete a journal/cache, relabel an unknown outcome as rollback, or
replay the installer to obtain a successful receipt.

A known provenance rejection with real exit21 can close as **failed**, preserving
that exit code, only after proving the exact unchanged source ZIP/MSI and revisions,
an unchanged terminal native journal, no pending transaction, private-file
continuity, services, restored user companions and a fresh180-second source-version
observation. The server requires a qualified executor and fresh matching WSS.
Other nonzero or unknown outcomes remain held for native recovery.

For the legacy observer1.0.3 hold on test120, authorized server maintenance calls
`request_client_recovery` rather than changing Windows files manually. It admits
only a fresh idle Foundation158/Core157 and an authenticated known-exit hold;
canonical Core163/return157 children keep that original hold committed. The server
also requires the exact return child to be applied/completed before accepting
source recovery. This recovery profile is qualified only on test120's existing
Foundation158/Core157; it is not a fresh Foundation156→158 qualification.

Client1.0.5 plans both fixed installed companions for logged-on ordinary WTS
sessions even when neither process existed before a SYSTEM installation. Each
launch uses a limited interactive token and validates the live SID, session,
fixed file path and release hash. Later logons are handled by a logon trigger
and bounded periodic maintenance against an accepted, unchanged native target.
Maintenance joins the canonical native/OTA mutex and preserves unresolved native
ownership. A maintenance error is reported without starving Endpoint polling.
No user password or manual companion-start task is required on the workstation.

Fleet control is documented in [FULL_SETUP_FLEET_POLICY.md](FULL_SETUP_FLEET_POLICY.md).

### Power loss during a 3.2.276 upgrade

If the recovery task returns 21, read the `status`, `stage`, `detail` and
`updated_at` fields in the local [Setup result](WINDOWS_UNIVERSAL_ENROLLMENT.md#diagnostics-and-failure-handling).
When Setup reports `INSTALL_FAILED / MSI / MSI_OUTCOME_UNCONFIRMED`, keep the
original operation open. Record the computer, boot time, operation ID from
`staged-update.json`, attempt ID and `native_exit` from its
`staged-recovery/<operation-id>/reboot.json`, and the recovery task's last
run time and result. These JSON paths are relative to
`%ProgramFiles%\Endpoint Platform\installer-state`. A missing record or
empty exit field leaves the outcome unknown.

For escalation, preserve the original protected installer state and
`install.log` on the device. The installer maintainer can use the two IDs
and the bound package identities to check whether Setup recorded the
authenticated end of that compound MSI transaction. A visible target EXE,
MSI product inventory or an MsiInstaller success event alone cannot establish
that the transaction committed. A normal reboot can resume a recorded
reboot-required outcome (3010 or 1641). Rebooting cannot supply a missing
outcome. Keep the hold if the affected attempt cannot be resolved.

The operator option `--recover-failed-core` requires an enrolled, installed
predecessor with a valid selector, the expected failed service and no active
installer transaction. On the Windows 10 .205 → .276 power-loss fixture the
selector was unreadable, neither MSI was registered and the services were
disabled. The boot task and the observed manual retry both returned 21.
The file for Core .276 was present, but Core was offline. [Native test evidence](../releases/windows-3.2.276-candidate.json)

## Immutable build inputs

When rebuilding an EXE around a reused MSI, provide `ExistingMsi`,
`ExistingMsiReleaseManifest`, `ExistingCoreArchive` and `InitialRuntimeStageRoot`
to `packaging/windows/build-setup.ps1`. The builder preserves the reused MSI's
signature and bytes, and verifies the original ZIP against the release and entire
runtime tree before copying it unchanged. Recompressing equal files can change
ZIP timestamps and therefore its hash; a protected existing cache rightly rejects
different bytes under the same MSI identity. Never overwrite an earlier revision.

The Setup manifest's source revision is the frozen native MSI/Core revision;
record a newer EXE-wrapper commit separately. Credentials, CA deployment inputs
and signing private keys stay outside Git. See the test120 verification receipt
for actual artifact IDs, timestamps, failed attempts and the accepted profile.
