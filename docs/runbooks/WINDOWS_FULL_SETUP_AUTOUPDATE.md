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

The current qualified observer is1.0.4. When preparation is required, server
`setup_updates.preparation.request_setup` creates canonical Core162 bootstrap
and exact Core157 return operations before the full Setup assignment. The Core
verifier installs the signed observer locally; its task and journal live outside
the MSI-owned Agent directory and survive full Setup. Readiness is not success.

Applied requires real Setup exit0, verified target Foundation/Core/source/MSI,
preserved credential/identity/origin/CA bytes, file IDs and owner/group/DACL,
restored surviving ordinary-user companions,180 seconds of runtime observation
and an independently verified fresh post-install WSS. The client reports the
sensor CPU measurements. No user password or administrator user session is needed.

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
canonical Core162/return157 children keep that original hold committed. The server
also requires the exact return child to be applied/completed before accepting
source recovery. This recovery profile is qualified only on test120's existing
Foundation158/Core157; it is not a fresh Foundation156→158 qualification.

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
