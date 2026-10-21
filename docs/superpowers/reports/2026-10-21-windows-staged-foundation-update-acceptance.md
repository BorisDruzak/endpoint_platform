# Staged Windows Foundation update acceptance

Status: **in progress; not accepted for production or fleet use**.

The source plan is `docs/superpowers/plans/2026-10-21-windows-staged-foundation-update.md`.
Only the dedicated disposable Windows guest is in scope. Historical artifacts,
snapshots and acceptance sequences remain unchanged.

## Rejected candidate 3.2.123

Runtime source: `5b9db8fecc8e9b7368a052a674af4504aa872b14`.
Clean build checkout: `bc7a97a8f87de5f157b06cca6b872dc37935f814`.
Exact-source [CI 39593369699](https://github.com/BorisDruzak/endpoint_platform/actions/runs/39593369699)
passed: 4414 tests, 728 skips. Supported Windows source gates passed:
2167 tests, 3 skips. These results do not establish installed acceptance.

| Artifact | SHA-256 |
| --- | --- |
| Signed MSI | `128cb5e27da8185918343336f49b69e9f8ba1066fa8f176315b10b5a3a11b341` |
| Signed Setup | `709b1a074b8edcf561364ec80cbd8dc516a9dc441ca0e8d512b42347e53c104d` |

Both signatures were valid with timestamp certificates. The isolated WiX 4.0.6
toolchain used an explicit matching Util extension DLL; global tools were not
changed. Frozen artifacts and detailed private controller evidence are retained
outside the repository.

The first genuine update used Foundation 3.2.120 with independently installed
Core 3.2.121. Online preparation took 24.65 seconds (14.68 seconds inside the
preparation operation, 820 owner grants taking 2.93 seconds). The old Agent
remained running through `prepared`. The saved runtime contained 111 files;
all file IDs, sizes and hashes matched after publication. Thus this observed
promotion wrote zero payload bytes. This is not the required 2500+ legacy-file
benchmark. Controller-held private comparison confirmed all four enrollment
leaf states were preserved, including the absent origin override.

The server observed Core 3.2.123, but policy application returned
`BROWSER_POLICY_HELPER_UNAVAILABLE`. Trial did not accept the candidate. The
owner stopped its services, then compensation failed with installer result 21
(`MSI_EVIDENCE_FAILED`). The journal remained `trial`; neither successful
automatic rollback nor the performance targets were proven. In particular,
the observed WSS outage exceeded two minutes.

A separate failure snapshot preserves the rejected state. Subsequent explicit
diagnostic recovery attempts are not automatic-rollback acceptance. A frozen
read-only probe confirmed original data, media, Foundation and Core proofs,
and exposed the provenance request mismatch below. The original guest snapshot
was restored; its clock was corrected and Core 3.2.121 reconnected to the server.

## Corrective source work

- `cc5717699c47cd9d4b933b8a468dce0dbbabc450` adapts the data-capture request to
  the five-field provenance contract, converts actual PowerShell JSON service
  state objects to validated hashtables, and keeps completed compound history
  out of post-switch forward-recovery admission. Native settlement still
  requires the authenticated helper and actual MSI barrier.
- `b543bc321d386dcd2a76b4a8efed8d0774722948` avoids full runtime hashing inside
  every Browser Policy pipe request during trial. Verification is cached for
  one listener lifetime and exact immutable binding/selector; caller identity,
  protected selector security and allowed lifecycle phase are checked again
  for each request.

Regressions were observed failing before the fixes. The corrective selection
passed 68 tests. Actual repeat acceptance requires a newly frozen version;
3.2.123 media and its manifest will not be replaced.

## Remaining admission

The success, early-crash and no-proof rollback cases on genuine 3.2.79 and
3.2.120 (including Core 3.2.121), identical-baseline cold/warm measurements,
interruption/reboot and remaining fault matrix are pending. The report verifier
withholds a complete pass when a scenario, native Foundation/Core proof,
private preservation check or measured performance target is missing.
