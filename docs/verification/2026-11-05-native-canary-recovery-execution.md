# Approved one-off native continuation recovery:27 and120

The operator explicitly approved recovery on both original machines. The existing
domain administrative SMB/SCM channel and pre-existing Microsoft-signed PsExec2.43
were used without SSH installation. Remote helpers run as SYSTEM in Windows
PowerShell5.1 with AllSigned; no interactive desktop launch is requested.

## Reviewed helper revisions

R1/R2 CheckOnly refused before agent-state writes. Generic namespace validation
incorrectly treated the legitimate service-writable enrollment DataRoot as an
administrative-only directory. The corrected read-only identity path pins the
DataRoot and leaf with retained no-follow handles, checks their actual handle
security descriptors and reads bounded identity bytes through that same handle.
Directory access includes FILE_LIST_DIRECTORY; sharing is read-only. Fixtures
prove DELETE/WRITE/rename/reparse/hardlink attempts fail while pinned.

R3 admits exactly the two equivalent orderings of the fixed service ALLOW ACEs;
owner/group/control flags, masks, ACE flags/count and all other descriptor fields
remain pinned. Native Windows ACL enumeration and .NET enumeration returned the
same permissions in different order. R4 additionally serializes exact integral
Decimal values to invariant integer JSON because PS5.1 uses Decimal for captured
Windows file IDs wider than UInt64. Fractional decimals and floating values remain
rejected; the immutable original capture SHA remains mandatory.

| Revision | Reviewed unsigned SHA256 | Signed SHA256 | Use |
| --- | --- | --- | --- |
| R3 | cee9f281050738c0b900782f652d4376da859d382207b570e23f2ecf4ab15d3c | 2d1c4f7ea2f7b2bcdf5093610b61b4c40a56414e06379a7a4719e58c9bad3068 |120 CheckOnly and Apply |
| R4 | 8d30972c3be98ecd7efec2648e4202ec3045b18d7afa25d7352661e736b6e61f | df449f4521738c513fbfcff76bcd39249ff39c68d706962a697d8396cf050b24 |27 CheckOnly and Apply |

Both immutable artifacts are timestamped AuthenticodeValid, publisher
4D4C23389F5FF77BC4EB32044761019EAE8FB776, under
`C:\endpoint-platform-wix-build\native-canary-recovery-r{3,4}-20261105`.
R3/R4 have independent source review and fresh real-ACL/native-handle fixture
passes, including RED-before/GREEN-after regressions. All mutation functions and
native scope pins remain unchanged from R1. R4's wide-integer vector was also
independently compared with Python canonical JSON SHA256 using PS5.1.

##120 observed result

R3 CheckOnly passed and Apply exited0. The original cached signed167 Setup ran
only `--recover-staged-update 568bfc6f-951d-4abe-89d5-abda265c2cd6`.
The helper created the missing protected observer1.0.6 directory and restored
the original grant-bound selector byte order, preserving exact backup/ACL:

- current: dc8e070cf7dc7fb1beff241e153fa75a56af9ceaf58efa3e7f166e3ef51e2086;
- backup: ddfeefe39f9dfb05b4397a2860a42bc7c45d8b326ffdc229837977eb9625029c;
- previous unchanged:6138efe66a5cbed3583130b74db5f173f9d7d531e545a25a29c91fc297d3d863.

The native continuation hold is absent. The original transaction completion marker
records grant SHA99fcba741574fcf9a39a3e7f4ed39b9597d2c38db638f2631d569c7c9af18b0a.
Installed observer1.0.6 has SHA
f6359376cac7f5a5de6476ed9c41ea652fb95fe7e64c285d1ff2eaa8f6b0b069,
valid timestamped publisher signature. At17:01Z the server saw observer1.0.6,
Core/Foundation167, policyAPPLIED, fresh UserSensor17:00:49Z and real
Activity17:01:19Z. No MSI installation/replay or manual companion launch occurred.

Original job0301db1b-38b2-40f1-91dc-3842e85fc66c retains native_exit21,
native_stageaccepted and phase recovery_required. Recovery-command exit0 is not
the original installation outcome. Server ownership remains held pending a
separate authenticated, audited FAILED/target-recovered proof; this result is
not APPLIED/native0 and does not qualify any release for fleet rollout.

##27 observation and remaining gates

R4 CheckOnly passed, including the actual original capture SHA; Apply exited0.
The original cached signed168 Setup ran only
`--recover-staged-update 1eeb0682-f3ac-4b79-8edf-eafdd5df8d83`.
The protected1.0.6 directory was created, native hold removed, and the original
transaction completion marker records grant SHA
627c33a1c3f86f06915fd49cecf903adebc19f0152de2a4908c8143f09aaca72.
Current selector7e07a3b9fd3429598df39c6b9db7ec01b1dfad709e41903acd66b9d4a73fce4e
and previous7e67a54eda493308256cb844c39ead5f5146c574584305482ccfe910b377d79c
are unchanged. The original jobe41d9fe1-628c-4279-b224-b7a4f55e7b99 still records
native_exit21, native_stageaccepted and phase recovery_required.

At17:07Z the server independently saw observer1.0.6/ready, Core/Foundation168,
policyAPPLIED, fresh UserSensor17:06:01Z and real Activity17:06:46Z on27.
120 remained fresh: UserSensor17:06:50Z and Activity17:06:50Z. API/worker
configuration was not changed by the workstation repairs. At this snapshot both
original server chains were held pending authenticated FAILED/native21 proof.
No manual UserSensor launch, MSI replay, grant/capture rewrite or private-data
replacement occurred.

Fleet revision3/all_active/max_parallel2 remains disabled. Full169 is separately
prepared and registered but has no native qualification or assignment. The
outgoing support tunnel remains design-only.

## Server reconciliation implementation

Commit ae1210bfe07103c8ba659aaf1166d2b1ea711f7b adds the device-authenticated
`native_failed_target_recovered` report: FAILED, original accepted/native21,
exact target/private proof, fresh180-second/6-sample active-sensor observation,
fresh qualified1.0.6 presence and post-install target WSS. The server separately
requires current APPLIED policy/digest, matching fresh sensor health and actual
Activity observations, completed preparation and no competing update ownership.
Unknown native outcome classification survives repeated reports and verifying
cycles; a diagnostic cannot promote unknown outcome into a known exit.
Identical Activity refreshes last_observed_at without changing the projection's
updated_at, so only the observation timestamp supplies Activity freshness.

Independent review cleared the final patch. Canonical Python3.12 verification:
183 passed in16.94seconds (one pre-existing Authlib deprecation warning):

`C:\Temp\endpoint-telemetry-repair-20261105\run-tests.ps1 tests/contracts/test_setup_updates.py tests/server/test_setup_target_recovery.py tests/server/test_setup_recovery.py tests/server/test_setup_update_service.py tests/server/test_setup_update_api.py tests/server/test_setup_fleet_policy.py -q`

`tools/contracts/generate_contract_artifacts.py --check` and `git diff --check`
passed. New regressions were observed failing before correction. GitNexus was
consulted but its indexed committed baseline has no record_progress symbol yet;
the current route/service source and authenticated API regressions verify this
project-specific path. No cross-repository API route or schema was added, no
database migration is required.

## Deployed server and authenticated completion

The canonical Console archive for280d5c2e3005f58c350885744c393af4eeaeeb7d
has SHA39e10099ec8887019936468c7e49f2c0da1514966ab68c1fc55173ce0b0e1b69,
465900bytes. npmci/typecheck/build passed (existing bundle-size warning).
Immutable candidate preparation preserved pinned dependencies; pipcheck,
configured application import and Alembic0045 current passed. Production was
promoted from75adbf4b414f with the old release retained for rollback. API/worker
are active; real HTTPS health returned200/databaseok with hostname and CA
verification. No schema migration or fleet enablement occurred.

The independently reviewed proof-only helper has reviewed source SHA
6d165164186d139cee7305a916bcc148597b4617cc1cb3eb91acf3ed8b6a2c71 and signed
SHA7e7383eafd79a80c9a27bf24c4a7d771f10bfc5dbab09d40c665b91f167b71fb,
33159bytes, valid timestamped publisher4D signature. Artifact:
`C:\endpoint-platform-wix-build\native-canary-completion-r1-20261105\Complete-EndpointNativeCanaries.ps1`.
Its exact signed1.0.6/R4 function imports do not expose installer, recovery,
service or companion launch operations. Both update mutexes are held in canonical
client-to-native order. CheckOnly writes no job/observation/API state. Apply
requires original job/attempt/source/native-ended pins, immutable grant and
finished marker, accepted stage, actual target preflight/private preservation,
fresh target companion processes and an actual WTSActive Sensor with matching
SID before and after a new observation. Canonical signed1.0.6 supplies the new
180second/6sample observation, native21 proof, authenticated hello and failed
report/journal acknowledgement. The helper never changes native21 into0.

Root and implementer PS5.1 fixture runs passed: healthy proof and21 negatives,
original job binding, immutable marker, source/private preservation, CheckOnly
zero writes/API/observation, fresh observation rather than cached soak, canonical
failed payload/ack, post-native process creation, disconnected-session and
changed-SID denial. The read-only WTS state wrapper was checked against current
Microsoft Win32 documentation after Context7 had no matching WTS API reference.
Independent final review cleared the helper. Both hosts passed CheckOnly before
Apply.120's initial CheckOnly rejected without writes; the pinned read-only
diagnostic rerun passed, so no cause is assigned to that first transient refusal.

| Host | Server finished UTC | Fresh soak | Sensor max CPU | Original outcome |
| --- | --- | --- | --- | --- |
|120 |17:20:47.924399Z |183.392s,6samples,1sensor |0.0064% |FAILED/accepted/native21, target167 recovered |
|27 |17:20:51.368817Z |182.023s,6samples,1sensor |0.0032% |FAILED/accepted/native21, target168 recovered |

Both canonical reports were accepted with safe_code
native_failed_target_recovered. Local phase is failed, no pending report;
server finished_at is set, original attempts/source Core/Foundation/client1.0.5
are preserved. Services/companions/connected are stable; all four private proof
flags are true and pending is false. Exactly one setup_updates.failed audit event
exists per original job. Server active native chains dropped from2 to0. At17:21Z
both clients1.0.6 remain ready with fresh UserSensor and real Activity; all source
health channels report READY. This is recovered failure history, not APPLIED or
release qualification.

Full169 remains registered/unqualified with no assignment. Fleet revision3 is
still disabled/max_parallel2. The operator Console session is now at the login
form; a repeat user login was requested before the next canary and fleet actions
through the web UI. No credential reset or administrative authentication bypass
was performed. The outgoing support tunnel remains design-only.
