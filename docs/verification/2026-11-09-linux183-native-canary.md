# Linux183 native release: qualified and published

Native Linux183 was published and its actual HTTPS bytes/signatures verified at
2026-11-09T11:15:10.810918Z. Windows177/policy12 are preserved. This qualifies the
dedicated native canary and publication, not a Linux fleet rollout. Legacy Core-only
OTA156 remains separate. [Exact release record](../releases/linux-3.2.183-native.json).

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

The ten pre-existing179/181 public executor snapshot directories were initially
inventoried and preserved.183 did not add a directory during clean install. Later,
only those exact unused public duplicates were reclaimed after fresh off-host
original-media checks and complete process-reference checks; native journals stayed
byte-identical. No historical installer bytes were lost. Completed public
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

Earlier182/181 results remain historical and do not silently qualify183. The
following final183 receipts supersede the initial in-progress checkpoint.


## Final native cycles and provider cause correction

All cycles retained Device5c51cb65, generation48238935 and private4. Ordinary
remove2/reinstall3 accepted native0/outer0/ACK3, preserved explicit manual disable,
and automatically consumed the exact active-session Sensor handoff. Root SSH was
refused while disabled; no new eight-hour grant appeared. Removal2 correctly kept
Support cleanup incomplete after the prior Support-token revocation test.

Offline remove4/install5 accepted native0, retaining delivery/registration pending
while the owned191→118 host-only route was blocked. After restoration, the server
received removed4 before installed5 and ACK5. Bootstrap then exposed a real
provider defect: a native key rebind advanced revision/generation but lost the
provenance of a prior explicit manual false. The next offline removal could not
capture a new exact ticket. No access was granted. A canonical real-administrator
registration reset and notification-only reconciliation recovered the original
pending5; its failed bootstrap history was preserved, with no RPM replay or SQL/
journal/fingerprint rewrite.

The first provider correction1511c0d was rejected by independent review for the
same failure after an authenticated online unregister. The second correction
fd196e7 carries exact audited disabled intent through both online and native
transitions. It binds actor/device, credential, predecessor audit, strict booleans,
revision/generation, revocation timestamp and persisted causal native events.
Historical unmarked evidence remains refused. Manual policy/revoke/reset changes
invalidate tickets; no automatic grant or expiry is renewed.

After independent re-review PASS, staging source0b8ea913 deployed the exact provider
fix while preserving Stage Worktime/schema51 and environment. Its first health
probe used an incorrect URL and automatically rolled back; the retained retry
used canonical /healthz and accepted at10:46:37Z. GatewayPID53228 was unchanged.

Actual fixed PostgreSQL/native proof:

| Step | Result |
| --- | --- |
| Online removed8,0715cf85-cf9e-4335-9901-816dececa773 | native0/outer0/ACK8; Support and browser cleanup complete |
| Installed9,44c1e1b5-6d9a-44a2-8134-27bed694daed | native0/outer0/ACK9; bootstrap/registration complete |
| Offline removed10,cadbf77a-b206-4ded-bcbc-aeb70bea2856 | native0/outer21 while disconnected; private4 unchanged |
| Offline installed11,cdb1cd1d-ec06-43ed-9282-74e74070f3aa | native0/outer21 while disconnected; then ACK11/bootstrap/registration complete after route restoration and canonical notification-only reconcile |

Route restored10:53:29.759520Z. No reset, manual native repair or RPM replay was
needed in these fixed cycles. Server audited authority transitions11→12→13 carried
strict false markers; row13 remained disabled with null expiry, generation7 and
exactly one original automatic grant. Unregister ambiguity on offline10 remains
incomplete in immutable history. The original permanent credential and card stayed.

Exact signed156 rollback6 and return1837 separately passed native0/outer0/ACK6/7.
The real restored Sensor executable used the nondeleted183 image. At10:39:01Z,
Core/Support had remained stable650.673001seconds with private4 and RPM verification
unchanged. This is package compatibility under the retained modern identity; it
is not an unattended qualification of every historical156 filesystem or identity.

## Final access, telemetry and UI

After final11, at10:58:04.306247Z Core1092275 and Support1092268 had zero restarts
and265.620710seconds of stable observation; private4 were unchanged, RPM-V0 and no
verification snapshot directory existed. Server accepted UserSensor10:57:40.071910Z,
healthREADY10:57:40.103244Z and activity10:58:15.073032Z.

A short explicit policy14 expired at10:57:27.688Z. A real strict-pinned root SSH
session ran10:56:32Z–10:57:20.160147Z, then closed before expiry. Native systemd
logs show sshd runtime timeout at15:57:20 local and tunnel timeout at15:57:23; both
children were inactive afterward. Core/Support parents continued unchanged. This
was a lease test, not a spontaneous client failure; the raw Windows SSH result
4294967295 is retained.

A separate authorized two-hour diagnosis policy15 was restored, expiring
13:00:41.039Z. A real root SSH command succeeded11:03:57.403863Z with the same
hardware UUID and stable Core/Support. Console operator attestation followed at
11:04:12Z; it is labelled as operator evidence, not a Console-executed command.
Host pins were updated only after authenticated rebind plus trusted local public
key derivation; predecessors remain archived and strict old-pin refusal was proven.

The real user-opened IAB Console session was used; no fake principal/session or
credential reset was created. Desktop,390px mobile and reload preserved the Linux
root/UID0 policy and attestation; no horizontal overflow at390px (scrollWidth375).
The previous-card history link is visible. The campaign label retains its historical
182 wording; the actual card reports Core/Foundation183. Screenshots are retained
outside Git at C:/endpoint-platform-wix-build/linux178-native/linux183-final-console-support.png
and linux183-console-mobile-support.png. AD, CUPS, applications and KDE session6
were preserved; no reboot/logout or employee input injection occurred.

## Production and actual served media

Production sourcefd196e78b2c5 deployed11:03:05Z–11:03:11.592237Z after a protected
51,311,972-byte database dump and configuration backup. Actual additive migrations
48→49→50 passed; Stage Worktime51 was excluded. New API334471/worker334472 and
exporter334584 were healthy. The gateway24963 and ordinary SSH889 did not restart.
Windows Support configuration, default campaign authority and fleet policy12/
all_active/max2 hashes stayed unchanged. Actual177 installer SHA remained9d06a833….
Only the five explicit Linux initial-default settings were added: approved existing
root/UID0/key, enabled after healthy installation report, maximum8hours.

Canonical native publisher, using actual Ubuntu RPM4.18.2 verification, registered
exact signed156 rollback source4c360770-c56e-412e-aa12-d5fc51c07db1 and new183 source
f785e4e5-17fd-414b-9474-0d1e24cf2100. Both header/payload signatures, complete payloads
and both detached kit signatures were verified; no agent RPM was installed on the
server. The initial new public directory retained a private umask; the Nginx read
check caught that and its exact owned directory mode was corrected to0755 without
changing artifact bytes or replaying publication. All eight public files are Root0644.

Actual canonical HTTPS HEAD/GET of all eight files matched exact hashes/sizes.
The71,370,015-byte archive SHA is
c5b552afa4aa27e4df73af0ce68be4ecc88729f30baf3a70e6f9d4c8c709a3f3.
The independently pinned public key and both downloaded detached signatures passed
operator verification; all archive members matched the signed manifest. TLS and
hostname checking stayed enabled. Directory listing and POST both returned403.
The operator Git GPG verifier required MSYS absolute paths; its initial local import
failure did not alter any served or signed bytes.

No Linux fleet campaign was enabled and no production enrollment authority expanded.
Existing-device upgrades use retained identity; a new Linux registration requires
separately bounded source-qualified campaign authority. The test VM stays on staging.
A working production Linux administrator SSH path is not inferred from this release.
Browser-specific/physical USB/printing and other distro/session/source profiles are
not newly qualified. Historical bytes, private identities and failure receipts remain.

## Verification and source commits

Executed covering checks include57 actual ALT tests (12 native), one actual built-RPM
probe,52 portable tests with13 explicit native/Windows skips, and real-exec negative
controls that failed the old coordinator twice. Final provider suite224 passed with
three existing warnings; independent re-review23 passed. Contract generation --check
and both exact production/staging Console typecheck/build passed (existing large
bundle warning). Actual Stage PostgreSQL/native flows and actual production49/50
migration are separate live evidence. The broad earlier provider baseline was not
repeated after this narrowly reviewed audit correction.

Exact provider command:

```text
C:/Users/admin-2/Documents/endpoint/.venv-device-binding/Scripts/python.exe -m pytest tests/server/test_linux_disabled_online_rebind.py tests/server/test_linux_disabled_rebind.py tests/server/test_linux_native_rebind_expiry.py tests/server/test_linux_support_lifecycle.py tests/server/test_linux_support_whole_seams.py tests/server/test_installation_lifecycle.py tests/server/test_support_access.py tests/server/test_support_install_access.py tests/server/test_support_console_platform.py tests/contracts/test_linux_support_lifecycle.py tests/contracts/test_installation_lifecycle.py -q
```

- `d365b5a0117b74b080bf65185dff7aaa49213136` — fix(linux): clean verification snapshots before executor handoff. Files: `pc_agent/platform/linux/installation_coordinator.py`, `pc_agent/tests/test_linux_native_executor_binding.py`, `tests/native/test_linux_installation_native.py`.
- `21fc543af8d4b8b24df83f29a27e4e2eeb86c268` — build(linux): prepare immutable 183 native candidate. Files: `packaging/alt/build-rpm.sh`, `pc_agent/version.py`, `tests/build/test_linux_native_candidate.py`, `tests/build/test_linux_native_manifest.py`, `tests/native/test_linux_installation_native.py`, `tools/build_alt_native_kit.py`, `tools/build_alt_pilot_kit.py`, `tools/build_linux_native_manifest.py`, `tools/release/freeze_linux_native_identity.py`.
- `aebc57e82cbafdff3a3b5282521f6180ae1e6ff3` — docs(linux): record 183 clean enrollment and reserve access. Files: `docs/releases/linux-3.2.182-native-candidate.json`, `docs/releases/linux-3.2.183-native-candidate.json`, `docs/verification/2026-11-09-linux182-native-canary.md`, `docs/verification/2026-11-09-linux183-native-canary.md`.
- `1511c0d23afe4d6df0d35daf7b5e94de765fe35a` — fix(support): retain disabled Linux rebind provenance. Files: `endpoint_server/installation_lifecycle/service.py`, `endpoint_server/support_access/disabled_intent.py`, `endpoint_server/support_access/native_rebind.py`, `tests/server/test_linux_disabled_rebind.py`.
- `fd196e78b2c5cef00c86de79ca359147676f8b2f` — fix(support): preserve disabled intent through online removal. Files: `endpoint_server/support_access/disabled_intent.py`, `endpoint_server/support_access/linux_routes.py`, `tests/server/test_linux_disabled_online_rebind.py`.
- `0b8ea9138011c1a4512737629d5a12b0269e4e7d` — fix(staging): preserve disabled Linux rebind provenance. Files: `endpoint_server/installation_lifecycle/service.py`, `endpoint_server/support_access/disabled_intent.py`, `endpoint_server/support_access/linux_routes.py`, `endpoint_server/support_access/native_rebind.py`, `tests/server/test_linux_disabled_online_rebind.py`, `tests/server/test_linux_disabled_rebind.py`.


## Owned cleanup and final state

At11:35:34Z the two exact owned182/183 build tmpfs mounts were released after
complete process-reference checks, retained native RPM/executor hash verification
and off-host media verification. This released779,956,375 regular-file bytes from
RAM scratch. The native store remained byte-identical, sequence11/ACK11/native0,
settled and bootstrap/registration complete. All private historical archives stay.
The ignored original operator input fixture is archived; its old scratch paths
are historical. Future diagnostics use the canonical retained signed inputs.

At11:36:08Z only the owned Stage compatibility clone
endpoint_linux178_compat_20261107/OID23520001 was dropped after zero-connection,
owner/marker and original-dump verification. The production Stage database
endpoint_staging_db/OID21026518, original dumps and all Worktime history remain.
Its exact temporary environment copy was removed; private proofs were retained.

At11:37:07Z production cleanup released172,152,523 bytes of verified duplicate
public inputs and the consumed temporary environment copy. The live configuration,
backup, native source rows, public historical/current media and receipts remain.
At11:37:30Z the exact disposable PostgreSQL16 process150382/UID110/datadir/port55446
was stopped with zero other clients and no remaining fixture databases. Its data
and log remain for history; production5432 was unchanged. The former Windows15446
forward/PID25032 was already absent; no unrelated process was stopped.

A fresh strict UUID-pinned root SSH command succeeded11:37:59.311741Z after cleanup.
Core1092275, Support1092268 and tunnel1095169 remained unchanged with zero restarts;
the original updater path was active and the updater/retry services were inactive.
Stage database verification11:38:32Z confirmed native11/installed, policy15/rootUID0,
fresh Support report11:38:14, accepted Sensor11:37:40.071312/READY, activity11:38:30.071131
and open WSS. The explicit diagnosis lease expires13:00:41.039Z and is not renewed.

Production verification11:39:02Z confirmed healthy HTTPS/database, sourcefd196e78,
schema50, the same API/worker/exporter/gateway/SSH processes with zero restarts,
exact Windows177 bytes/policy12/campaign/support authority and all eight published
Linux file hashes. Root free space was756,146,176 bytes; no resize was performed.
The final scoped release-document review passed after correcting stale historical
provider metadata. No code changed after the224-test provider run and23-test review.
JSON/media consistency, generated contracts and whitespace checks were repeated for
the final documentation commit. [Controller rulings](2026-11-09-linux183-rulings.md)
remain reviewable; recovery evidence and this active worktree are preserved.


Final documentation commit includes only these eleven files:

- AGENTS.md
- deploy/server/endpoint-platform.env.example
- docs/releases/current-agent-release.json
- docs/releases/linux-3.2.183-native-candidate.json
- docs/releases/linux-3.2.183-native.json
- docs/runbooks/ALT_AGENT_INSTALL.md
- docs/runbooks/INDEPENDENT_SUPPORT_ACCESS.md
- docs/runbooks/LINUX_NATIVE_SETUP.md
- docs/superpowers/plans/2026-11-07-linux-support-lifecycle.md
- docs/verification/2026-11-09-linux183-native-canary.md
- docs/verification/2026-11-09-linux183-rulings.md

Final documentation checks: `git diff --check`,
`python tools/contracts/generate_contract_artifacts.py --check`, and the guarded
operator `final_release_records_check.py` all passed. The latter compared the
Windows/campaign/policy objects and preserved156/provider snapshots against Git
HEAD and rehashed all eight served files and both signed native RPMs. These checks
do not claim another full provider-suite execution.
