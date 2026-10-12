# Task13 read-only investigation after recovery F

Status: investigation incomplete; no repeat seq04 and no correction claimed.
The actual F guest failure and both occupied recovery slots remain immutable.

Separate, reviewed read-only probes inspected selected baseline fields without
calling Facts, PublicProof, a comparator dispatcher or an execution admission
path. Native source/history/runtime handles were retained across observation.
All five consumed claims, original records, F and prior probes were preserved.
Private file bodies, hashes, SDDL strings and private identities were excluded
from diagnostic output.

## Confirmed current observations

The exact protected baseline hash was verified. Its length is 2,561,556 bytes.
It contains no non-ASCII characters; default PowerShell reading equals strict
UTF-8 reading. An encoding mismatch is not supported for this baseline.

MSI cache content and ACL match the baseline. Both update journals' content and
ACL match. The credential and CA file content/ACL also match. Enrollment identity
content matches, but its SDDL string does not match the baseline. No change was
made to that file or its permissions.

This is a proven current discrepancy in a field included by the exact Facts
comparison. The precise permission difference, its writer/timing, and linkage
to the historical F exception are not yet established. No historical exception
message or failed predicate is reconstructed from these new observations.

## Diagnostic refusals and review

An initial local diagnostic preflight incorrectly required protected DACLs on
legacy receipts. It stopped before target dispatch. The unchanged historical
loader already verifies and retains their trusted owner and DACL with inherited
ACLs permitted. The corrected diagnostic driver reused that exact check; it did
not modify receipt ACLs or weaken execution guards.

The first target probe refused without detailed output. A separately preserved
probe added sanitized checkpoint/class/HResult/source-line output and localized
its own refusal to a case-sensitive cache-path filter. Windows path matching in
the subsequent read-only probe requires a string and the same fixed Installer
path pattern while honoring Windows case insensitivity. This diagnostic-tool
correction is not an explanation or fix of the historical F failure.

The successful field observation has status READONLY_BASELINE_FIELDS_OBSERVED,
with seq04_dispatched=false and claims_created=false. Its independently reviewed
held gate SHA256 was
17ac1421737d7b7c421624babcc2912dcdb458d4d9ad7bfeb74ebcd1da49ac2d.
The probe source SHA256 was
260860fd147944736452fa3e05b093ced631e0bc667bb16e2b9bdab197c4df37.
Full command lengths were 7,808 UTF-16 units including NUL locally and 7,671
for the remote shell layer; existing bounds remained unchanged.

Only current read-only evidence was added. Original plan, seal, deadlines,
00–03 receipts, sealed Facts, baseline, snapshot, consumed claims, runtime,
MSI and Setup were not changed. No marker, restore or rollout was performed.
There is still no accepted receipt04/RootCompletion or authority for forward
execution. A Git publication does not change those admission conditions.
