# Elevated Windows installer owner and recovery correction

The user authorized correcting Setup and installing/testing it on A2-INFAN-N
(`192.168.101.29`). Original 149 failed assigning SYSTEM ownership during
reconciliation (1307). Its Agent/install.log then contaminated the authenticated
fresh-root recovery expectation. Running Setup elevated was independently verified.

## Approach

Preserve the original selector owner and exact DACL. Temporarily enable an
already-held SeRestorePrivilege on the effective token around owner transfer,
then restore its prior attributes on success and failure. Do not grant privileges
to an account, change machine policy, replace SYSTEM with an administrator, or
broaden file access. A token lacking that privilege retains normal Windows checks.
Keep Setup diagnostics in its separately protected Installer directory so failed
fresh installations leave Agent data untouched. Retain the strict empty-root and
credential-preservation gates rather than accepting arbitrary residue.

## Verification and delivery

Native NTFS regressions must cover disabled/enabled/missing privileges, exact owner
and DACL preservation, failure cleanup, and effective impersonation tokens.
Setup tests must show that failure and retry do not add anything to a fresh Agent
directory. Build signed, source-bound MSI/Setup as a distinct candidate version.
Back up existing 149 evidence, recover its exact existing transaction with original
media and scoped operator privilege where required, then test the corrected
candidate on the same PC. Never clear a transaction fence or erase enrollment
material to force success. Do not publish a fleet rollout or change GPO scope.
