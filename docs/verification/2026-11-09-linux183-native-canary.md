# Linux183 immutable candidate: ongoing native acceptance

This record is in progress. Production Linux156 and Windows177 remain published.
Linux183 has not been promoted or fleet-qualified.

## Source, fix and actual native tests

Source `21fc543af8d4b8b24df83f29a27e4e2eeb86c268` includes
`d365b5a0117b74b080bf65185dff7aaa49213136`. The executor now leaves its verified
snapshot context before successful POSIX `execv`; all existing retention and
identity checks remain. Signed182 bytes retain their confirmed leak and are
rejected; no historical package was overwritten.

Actual ALT checks: 57 passed, including 12 native cases and both real-exec cases.
A scoped subprocess import of the previous coordinator reproduced two expected
real-exec failures. The fixed coordinator passed. A structural test against the
actual built183 RPM also passed. Native checks had no skips; three existing
isolated-harness configuration warnings remain. Portable candidate checks passed
52 tests with 13 explicit Windows/native skips. Independent review passed.

The [candidate record](../releases/linux-3.2.183-native-candidate.json) binds actual
signed RPM, embedded Setup, complete frozen manifest, kit and detached signatures.
Staging registered source `0279b8fa-adf6-4658-b7d4-b0eddbf6ca3c` at
`2026-11-09T10:03:32.162879Z` through the mandatory native verifier.

## Clean installation and genuine parent relationship

VM107 remains `alt-a2-pc86.sosnadmin.local`, `192.168.101.191`, product UUID
`db12fb5c-3732-487f-911f-80e31f79b29b`. AD and the active KDE session were preserved.
The preceding modern182 card `ebd42535-32e7-4443-95a4-20da3cb0b157` had confirmed
native removal2/ACK2 and complete cleanup. Its roots and private history were
archived separately, and its lost credential was revoked with canonical audit.

Fresh183 used new configuration installation ID
`5394bb48-dade-4d2c-a0c9-c53be848481e`, without copying prior identity or credential.
Install `1cb4f59b-ce86-40fb-bba6-cbea58017f76` ran once,
`10:09:02.794453Z`–`10:09:25.987616Z`, native0. Initial outer21/sequence0 correctly
represented pending manual enrollment, not an RPM failure. Actual Console approval
of request `db6657de-700d-4fc6-8feb-58d1a481ad00` linked the confirmed removed
modern182 parent. The canonical bootstrap reconciliation completed without RPM
replay: installed1/ACK1, generation `48238935-7663-4ac3-8102-fe978093d0e6`, Device
`5c51cb65-4ccd-4f19-87bc-b06c088d1e1a`. Server received installed1 at
`10:10:40.563072Z` and reports the exact previous Device ID above.

The unrelated legacy156-derived card remains separate: its earlier canonical
fingerprint comparison failed closed. No digest, request, claim or history was
rewritten to force a link.

The ten pre-existing178/181 public executor snapshot directories were inventoried
and preserved.183 did not add a directory during clean install. Completed public
build caches were reclaimed only after complete off-host archival/verification;
no private journal, identity or product ownership metadata was purged.

## User session and automatic reserve access

The existing device-only telemetry policy was assigned to the new card through
the actual administrator session. The standard XDG autostart entry point was
explicitly run as UID1000 in genuine active X11/KDE session6. This is not proof
that a newly installed package can replay a graphical login automatically.
Accepted sensor-health observation `10:12:43.113901Z` was fresh/READY; Console
also showed advancing Activity Sensor observations.

Support1.0.0 automatically received the existing approved root/UID0/operator-key
policy, revision2, expiring `18:10:41.647320Z` (eight hours). Its authenticated host
public key matched the public derivation from the protected local private key.
An actual strict UUID-pinned root command succeeded at `10:12:05.248885Z`, through
the existing staging bastion. Registration/tunnel status alone was not counted
as administrative access. CorePID1066442 and SupportPID1066433 had zero restarts.

Core/update/path were stopped at10:12:58Z. Strict root commands succeeded at
10:13:00.514194Z and10:14:49.127824Z, separated by108.613629715 kernel boot
seconds, with an additional intermediate command. SupportPID1066433 and tunnel
PID1066652 remained unchanged. Core and its update path were restored at
10:14:50.752309Z; the owned five-minute fallback timer was then stopped.
At10:18:04.114470Z, CorePID1067864 had run193.320695seconds without restart,
Support remained1066433, Sensor1067252 was active, private4 were unchanged and
both RPMs verified without differences. Fresh accepted post-restore sensor
health at10:16:52.211579Z was READY.

A genuine root SSH session was held from10:16:09Z. Console administrative revoke
returned204; the session closed withSSH255 at10:16:31.935511Z. This proves remote
channel revocation, not immediate destruction of every local loopback process.
The existing bounded policy was explicitly recovered without extending its
original deadline, then manually disabled for the ordinary-reinstall test.

Ordinary/offline native cycles and final release gates remain in progress.
Earlier182/181 results remain historical and do not silently qualify183.
