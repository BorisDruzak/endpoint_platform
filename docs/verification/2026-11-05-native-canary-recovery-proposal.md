# Bounded recovery proposal: original27/120 native continuations

Status: the operator explicitly authorized the one-off administrative recovery
on both101.27 and101.120 on2026-11-05. This is a scoped exception to the normal
Endpoint-only update path. The original proposal and immutable R1 evidence below
are historical; live execution uses separately reviewed, signed immutable R3/R4
helpers described in `2026-11-05-native-canary-recovery-execution.md`.

## Exact artifact and verification

Signed local artifact:
`C:\endpoint-platform-wix-build\native-canary-recovery-r1-20261105\Repair-EndpointNativeCanaries.ps1`.
SHA256bb9c7b661b124882fc05c87f94147a1b3cab584371e660206b862f128463875a,
44397 bytes; AuthenticodeValid, timestamped, publisher
4D4C23389F5FF77BC4EB32044761019EAE8FB776.
Reviewed unsigned source SHA256872ec65a10526fc4cd9f6d4089482e65b8c17e7c58b357dfed4a7df075b7a60f.
Signed body was compared against the exact reviewed/tested source after normalizing
line endings and excluding the signature block: identical.

Windows PowerShell5.1 isolated fixture tests passed before signing and against
the signed copy's extracted functions. The helper's main dispatcher was never
executed against a real host. Coverage includes15 negative scope cases, retained
process death proof, exact stock mutex functions under an isolated local test
name, protected directory creation, real atomic selector replacement/backup,
exact owner/group/DACL preservation, unsafe parent and ordinary/broken reparse
rejection. Token tests explicitly initialize disabled/enabled SeRestorePrivilege
and verify exact state restoration on normal and exceptional exits. Independent
review found and corrected a restoration defect before signing; the final
reviewed source has no outstanding material findings.

The source and fixture-test files are operator build inputs under
`C:\Temp\endpoint-setup165-20261105`; they are not a general privileged endpoint
or a release update client. All testing used temporary local fixtures; no
canonical machine update mutex or production job was mutated by the tests.

## Proposed changes

| Host / original job | Narrow preparation | Native action |
| --- | --- | --- |
| A2-MUNSLU-N /101.27; e41d9fe1-628c-4279-b224-b7a4f55e7b99 | Create only the missing protected ProgramFiles observer1.0.6 directory | Original signed cached168 Setup `--recover-staged-update 1eeb0682-f3ac-4b79-8edf-eafdd5df8d83` |
| DESKTOP-9ST5HO2 /101.120;0301db1b-38b2-40f1-91dc-3842e85fc66c | Create the same missing protected directory; atomically normalize only the existing167 selector key order back to its ORIGINAL grant hash, with exact backup/ACL | Original signed cached167 Setup `--recover-staged-update 568bfc6f-951d-4abe-89d5-abda265c2cd6` |

Directory ACL is protected SYSTEM/Administrators FullControl. Existing root ACLs
and old1.0.5 client bytes are preserved. On120 current selector changes only from
ddfeefe39f9dfb05b4397a2860a42bc7c45d8b326ffdc229837977eb9625029c to
dc8e070cf7dc7fb1beff241e153fa75a56af9ceaf58efa3e7f166e3ef51e2086.
Version167, sourceab313225e04b7cccefc0c30ae17b949d8fdd964d, previous6138efe66a5cbed3583130b74db5f173f9d7d531e545a25a29c91fc297d3d863,
and candidate tree5d81e12d78d07c2caca984c5ee3614299825c454befeb44a2eb35629be74f9ce
remain unchanged. The selector's exact existing ownerBA/groupSY/protectedPAI
security descriptor and service read permissions are preserved.

## Authority and limits

The helper defaults to CheckOnly. Apply requires exact allowlisted host,
enrollment UUID, original job/attempt/operation, accepted native exit21, immutable
package/source/capability/grant/capture pins, matching candidate tree and selectors,
trusted non-reparse namespaces and retained death proof for previous native and
recovery owners. Cached Setup and MSI are pinned and require genuine timestamped
signatures from the fixed publisher. The wrapper/helper/release bytes are pinned
to their original authenticated MSI/cache inputs. Only the two canonical mutex
functions are imported from the hash-pinned original wrapper.

The canonical update mutex is held through revalidation and the narrow changes,
then released before stock Setup establishes its own original recovery authority.
The original helper still performs its own immutable grant/capture/MSI/owner gates.
No arbitrary helper replacement, grant rewrite, ACL relaxation, manual UserSensor
launch, native installation or MSI replay is authorized by this proposal.

Success means the original native continuation finished and preflight verifies
the exact target with no pending state. The original native exit21 and job
history remain unchanged, **not APPLIED/native0**. Fresh user telemetry must then
be checked separately. A truthful, audited server/client reconciliation of these
already-failed jobs is still required before releasing their server ownership;
the prepared helper does not manufacture that outcome or enable fleet policy.
A partial failure retains evidence and must be reviewed before any further action.

The standalone169 candidate contains the prospective code fixes, but is not
authority to adopt or erase either existing native recovery hold. It has no live
qualification or assignments. The separate outgoing support tunnel remains
design-only; this preparation did not install SSH or another remote-access channel.
