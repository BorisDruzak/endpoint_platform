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
configuration was not changed by the workstation repairs. Both original server
chains remain held pending authenticated FAILED/native21 target-recovery proof.
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
database migration is required and deployment is still pending at this record.
