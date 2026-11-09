# Windows184: retained first-start failure on test120

Scope: DESKTOP-9ST5HO2 /192.168.101.120, Device
c87eaa22-4fd1-4830-bc11-88142afda87e only. Primary Windows177 and Linux183,
fleet12/target177/max2 remain unchanged. No184 qualification or promotion.

The immutable signed [184 record](../releases/windows-3.2.184-setup.json) binds
runtime7b20706e6c87eb17cd280e278d3db5ac99744ed4 and packaging
6e208e42594a1c82c6f8f80d8c70b4f32102a1dd. MSI/EXE/Support signatures,
frozen source and independent import closure were inspected. Support1.1.0 omits
the portable Preview ZIP/SSH executables; metadata for owned cleanup remains.
Windows tests:2572 passed,4 skipped; runtime-contract tests:14 passed.

An earlier read-only signed preflight caught Windows servicing hardlinks being
rejected by the private-file helper. The OS-specific fix retains trusted
owner/write ACLs, signatures and ancestor reparse rejection; private identity
single-link rules remain unchanged. The corrected signed preflight validated
all12 Microsoft9.5.6.4 PE files on120. Both capabilities were already installed:
this does not qualify actual missing-FoD installation or reboot.

## Native update and delivery interruption

Console assigned177/client107 to184, assignment
013f47e7-27c2-4472-9aec-239d342cf380, attempt
d93d73a4-c4fe-4520-af98-963cf47e75d1. An intentional idle observer pause
retained the assigned job and actual administrator reserve SSH; enabling the
original task resumed work after29.9854162seconds.

The first download failed at19:24:09Z, before native start. Nginx logged a short
write to its disk proxy buffer. Publication inputs had left insufficient space
for another full EXE buffer. Exact owned public staging duplicates were removed
after hash comparison with retained operator originals and the live artifact.
No historical artifact, private backup or native journal was removed. The
unchanged task retried with the same assignment/attempt; the complete EXE was
verified, and native execution started19:25:50.520491Z. The runbook now requires
response-buffer capacity and operational margin before canary assignment.
No server restart or Nginx configuration change was made.

APPLIED/native0 was accepted at19:35:56.324185Z: Core/Foundation184,
185.318seconds,6 samples,1 sensor, stable services/companions, fresh connection,
native/provenance/private4 checks all true. Native success remains independent
from Support failure below. Original job and failure receipts remain.

## Support first-start failure

Before migration, Support had no readiness.json. First1.1.0 activation returned
support_install_failed and restored signed1.0.1 plus its compatible configuration.
Real domain administrator reserve SSH then succeeded; private4, Support keys and
credential, policy revision3/generation1 and expiry were unchanged. The existing
global OS SSH service/configuration/firewall were untouched.

The parent masks unexpected exceptions, so no retrospective traceback exists for
that attempt. Investigation reproduced the first-publish race: GetNamedSecurityInfo
on an absent readiness file raises pywintypes.error2, which is not OSError and
escaped the readiness wait. SCM Running can precede publication. Regression tests
reproduce errors2/3; error5 remains fatal. The fix waits within the existing
deadline for exact authenticated proof and never counts absence as readiness.
It will ship in a new immutable185.

Two bounded canonical Support reproductions under SYSTEM, after the record
existed, succeeded with unchanged signed1.1.0: an instrumented exact-profile
wrapper and original --install CLI. This administratively prepared result does
not qualify unattended177 migration. A generic diagnostic missing the build
interpreter's public SSL policy resource failed before registration; its fixture
and logs were retained and replaced by an exact-profile diagnostic.

The next test restores177 by ordinary native uninstall/reinstall, retaining the
card/history/private identity. No recursive product purge or readiness-file
deletion manufactures first-start state. The existing global SSH public key was
read through authenticated reserve access and strictly pinned before rebaseline;
that is control access, not reserve-channel acceptance.

Operator evidence is outside Git under
C:/endpoint-platform-wix-build/windows184-inbox-20261109. No private credential,
private key, session cookie or private-file hash is committed here.
